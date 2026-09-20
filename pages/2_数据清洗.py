import streamlit as st
import pandas as pd
import numpy as np
import re
import json

st.set_page_config(page_title="数据清洗与校验", layout="wide", initial_sidebar_state="expanded")

#1. 初始化会话状态
if 'clean_df' not in st.session_state:
    st.session_state['clean_df'] = None
if 'clean_report' not in st.session_state:
    st.session_state['clean_report'] = None
if 'clean_raw_count' not in st.session_state:
    st.session_state['clean_raw_count'] = 0
if 'clean_final_count' not in st.session_state:
    st.session_state['clean_final_count'] = 0
if 'clean_triggered' not in st.session_state:
    st.session_state['clean_triggered'] = False
if 'clean_mapping_confirmed' not in st.session_state:
    st.session_state['clean_mapping_confirmed'] = False
if 'clean_df_before' not in st.session_state:
    st.session_state['clean_df_before'] = None

#2. 侧边栏：文件上传
st.sidebar.header("数据管理")

if st.session_state['clean_df'] is None:
    uploaded_file = st.sidebar.file_uploader("请上传日志文件 (CSV 或 JSON)", type=["csv", "json"])
    if uploaded_file is not None:
        if uploaded_file.name.endswith('.csv'):
            df_temp = pd.read_csv(uploaded_file)
        elif uploaded_file.name.endswith('.json'):
            df_temp = pd.read_json(uploaded_file, lines=True)
        else:
            st.sidebar.error("暂不支持该文件格式。")
            st.stop()
        st.session_state['clean_df'] = df_temp
        st.session_state['clean_raw_count'] = len(df_temp)
        st.session_state['clean_triggered'] = False
        st.session_state['clean_mapping_confirmed'] = False
        st.session_state['clean_df_before'] = None
        st.rerun()
else:
    st.sidebar.success("数据已加载")
    if st.sidebar.button("重新上传数据"):
        st.session_state['clean_df'] = None
        st.session_state['clean_report'] = None
        st.session_state['clean_triggered'] = False
        st.session_state['clean_mapping_confirmed'] = False
        st.session_state['clean_df_before'] = None
        st.rerun()

#3. 标准字段识别与用户选择
df = st.session_state['clean_df']

if df is not None:

    def get_standard_columns(dataframe):
        mapping = {
            'Label': ['Label', 'label', 'Class', 'class', 'Attack Type', 'attack_type', 'target', 'Attack', '攻击类型', '类别'],
            'Port Number': ['Port Number', 'port', 'Port', 'dst_port', 'Destination Port', 'destination_port', 'port_no', '端口', '端口号'],
            'Received Bytes': ['Received Bytes', 'received_bytes', 'recv_bytes', 'bytes_in', 'in_bytes', '接收字节', '接收字节数'],
            'Sent Bytes': ['Sent Bytes', 'sent_bytes', 'send_bytes', 'bytes_out', 'out_bytes', '发送字节', '发送字节数']
        }
        identified = {}
        for std_name, aliases in mapping.items():
            for alias in aliases:
                if alias in dataframe.columns:
                    identified[std_name] = alias
                    break
        missing = [std for std in mapping.keys() if std not in identified]
        return identified, missing

    identified_cols, missing_cols = get_standard_columns(df)

    # 用户选择：仅在缺列且尚未确认时展开
    if missing_cols and not st.session_state['clean_mapping_confirmed']:
        with st.sidebar.expander("手动列名映射设置", expanded=True):
            with st.form("mapping_form"):
                st.warning("以下关键字段未能自动识别，请手动指定；若不处理，系统将跳过相关步骤：")
                user_selections = {}
                for std_name in missing_cols:
                    options = ["未找到"] + df.columns.tolist()
                    user_choice = st.selectbox(
                        f"请选择【{std_name}】对应的列名：",
                        options=options,
                        key=f"clean_user_{std_name}"
                    )
                    user_selections[std_name] = user_choice

                submitted = st.form_submit_button("确定", use_container_width=True, type="primary")
                if submitted:
                    for std_name, choice in user_selections.items():
                        if choice != "未找到":
                            identified_cols[std_name] = choice

                    rename_dict = {}
                    for std_name, actual_name in identified_cols.items():
                        if std_name != actual_name:
                            rename_dict[actual_name] = std_name
                    if rename_dict:
                        df = df.rename(columns=rename_dict)
                        st.session_state['clean_df'] = df

                    st.session_state['clean_mapping_confirmed'] = True
                    st.rerun()

        # 未确认前，暂停清洗流程
        st.title("数据清洗")
        st.info("请在左侧侧边栏完成列名映射后，点击【确定】以继续。")
        st.stop()
    else:
        # 自动识别成功，或用户已确认，直接执行重命名
        st.session_state['clean_mapping_confirmed'] = True
        rename_dict = {}
        for std_name, actual_name in identified_cols.items():
            if std_name != actual_name:
                rename_dict[actual_name] = std_name
        if rename_dict:
            df = df.rename(columns=rename_dict)
            st.session_state['clean_df'] = df

    #4. 清洗函数
    def remove_duplicates(dataframe):
        before = len(dataframe)
        dataframe = dataframe.drop_duplicates()
        removed = before - len(dataframe)
        return dataframe, f"去重：删除了 {removed} 行重复数据（剩余 {len(dataframe)} 行）"

    def handle_missing(dataframe):
        missing_count = int(dataframe.isnull().sum().sum())
        if missing_count == 0:
            return dataframe, "缺失值处理：未发现空值，无需处理"
        dataframe = dataframe.dropna()
        return dataframe, f"缺失值处理：发现 {missing_count} 个空值，已删除含空值的行（剩余 {len(dataframe)} 行）"

    def normalize_labels(dataframe):
        if 'Label' not in dataframe.columns:
            return dataframe, "标签标准化：未找到 Label 列，跳过"
        alias_map = {
            'portscan': 'PortScan', 'port scan': 'PortScan', 'portscanner': 'PortScan',
            'tcp-syn': 'TCP-SYN', 'tcp syn': 'TCP-SYN', 'tcpsyn': 'TCP-SYN',
            'blackhole': 'Blackhole', 'black hole': 'Blackhole',
            'diversion': 'Diversion', 'normal': 'Normal', 'overflow': 'Overflow'
        }
        before = dataframe['Label'].nunique()

        def _normalize(val):
            v = str(val).strip().lower()
            return alias_map.get(v, str(val).strip())

        dataframe['Label'] = dataframe['Label'].apply(_normalize)
        after = dataframe['Label'].nunique()
        return dataframe, f"标签标准化：原有 {before} 种标签，规整后 {after} 种"

    def validate_port_range(dataframe):
        if 'Port Number' not in dataframe.columns:
            return dataframe, "端口校验：未找到 Port Number 列，跳过"

        def _extract_port(val):
            nums = re.findall(r'\d+', str(val))
            return int(nums[0]) if nums else None

        dataframe['Port Number'] = dataframe['Port Number'].apply(_extract_port)
        invalid_mask = (dataframe['Port Number'] < 0) | (dataframe['Port Number'] > 65535) | (dataframe['Port Number'].isnull())
        invalid_count = int(invalid_mask.sum())
        dataframe.loc[invalid_mask, 'Port Number'] = pd.NA
        return dataframe, f"端口校验：发现 {invalid_count} 个非法端口（超出 0-65535 范围），已标记为缺失"

    def convert_types(dataframe):
        converted = []
        for col in ['Port Number', 'Received Bytes', 'Sent Bytes']:
            if col in dataframe.columns:
                dataframe[col] = pd.to_numeric(dataframe[col], errors='coerce')
                converted.append(col)
        if converted:
            return dataframe, f"类型转换：已将 {', '.join(converted)} 转换为数值型"
        return dataframe, "类型转换：无需转换的列"

    #自动清洗
    if not st.session_state['clean_triggered']:
        st.session_state['clean_df_before'] = df.copy()

        report = []
        df, msg = remove_duplicates(df)
        report.append(msg)
        df, msg = handle_missing(df)
        report.append(msg)
        df, msg = normalize_labels(df)
        report.append(msg)
        df, msg = validate_port_range(df)
        report.append(msg)
        df, msg = convert_types(df)
        report.append(msg)

        st.session_state['clean_df'] = df
        st.session_state['clean_report'] = report
        st.session_state['clean_final_count'] = len(df)
        st.session_state['clean_triggered'] = True

    #6. 页面渲染
    df = st.session_state['clean_df']
    report = st.session_state['clean_report']
    raw_count = st.session_state['clean_raw_count']
    final_count = st.session_state['clean_final_count']

    # 下载
    col_title, col_dl = st.columns([7, 1])
    with col_title:
        st.title("数据清洗")
    with col_dl:
        with st.popover("下载数据", use_container_width=True):
            st.markdown("**选择下载格式：**")
            csv_data = df.to_csv(index=False).encode('utf-8-sig')
            st.download_button(
                label="CSV 格式",
                data=csv_data,
                file_name="cleaned_log.csv",
                mime="text/csv",
                use_container_width=True
            )
            json_data = df.to_json(orient='records', lines=True, force_ascii=False).encode('utf-8')
            st.download_button(
                label="JSON 格式",
                data=json_data,
                file_name="cleaned_log.json",
                mime="application/json",
                use_container_width=True
            )

    # 清洗报告
    if report is not None:
        retention = (final_count / raw_count * 100) if raw_count > 0 else 0
        items_html = "".join([f"<li style='margin: 8px 0;'>{item}</li>" for item in report])
        st.html(f"""
        <div style="background-color: #ffffff; border: 1px solid #e2e8f0; 
                    padding: 20px; border-radius: 8px; margin-bottom: 20px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.08);">
            <h4 style="margin: 0 0 12px 0; color: #1e293b;">清洗报告</h4>
            <p style="margin: 4px 0; color: #64748b;">
                原始数据：<b>{raw_count:,}</b> 行 &nbsp;&rarr;&nbsp; 
                清洗后：<b>{final_count:,}</b> 行 &nbsp;|&nbsp; 
                保留率：<b style="color: #16a34a;">{retention:.1f}%</b>
            </p>
            <ul style="margin: 12px 0 0 0; padding-left: 20px; color: #334155;">
                {items_html}
            </ul>
        </div>
        """)

    # 数据预览
    st.markdown("**数据预览**")
    st.dataframe(df.head(20), use_container_width=True)

    # 7. 数据错误行展示
    st.markdown("**数据错误行展示（最多 20 行）**")

    error_rows_list = []
    df_before = st.session_state.get('clean_df_before')

    # 1. 被删除的行
    if df_before is not None:
        removed_indices = set(df_before.index) - set(df.index)
        if removed_indices:
            removed_rows = df_before[df_before.index.isin(removed_indices)].copy()
            removed_rows.insert(0, '错误类型', '重复或含缺失值')
            error_rows_list.append(removed_rows)

    # 2. 端口非法的行
    if 'Port Number' in df.columns:
        invalid_port_rows = df[df['Port Number'].isnull()].copy()
        if not invalid_port_rows.empty:
            invalid_port_rows.insert(0, '错误类型', '非法端口')
            error_rows_list.append(invalid_port_rows)

    if error_rows_list:
        all_errors = pd.concat(error_rows_list, ignore_index=True).head(20)
        st.dataframe(all_errors, use_container_width=True)
    else:
        st.info("未发现数据错误行。")

else:
    st.title("数据清洗")
    st.markdown("""
    本模块上传的网络安全日志将进行简单清洗：
    - 去除重复行
    - 处理缺失值
    - 攻击标签标准化
    - 端口范围校验
    - 数据类型转换
    
    请从左侧上传日志文件开始。
    """)
    st.info("请从左侧侧边栏上传日志文件，系统将自动执行清洗流程。")