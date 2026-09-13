import streamlit as st
import pandas as pd
import plotly.express as px

# 1. 页面设置
st.set_page_config(page_title="网络安全日志分析平台", layout="wide")
st.title("🛡️ 网络安全日志分析与可视化平台")
st.markdown("上传你的网络日志，快速洞察攻击趋势。")

# 2. 侧边栏：文件上传（支持 CSV 和 JSON）
st.sidebar.header("数据管理")
uploaded_file = st.sidebar.file_uploader("请上传日志文件 (CSV 或 JSON)", type=["csv", "json"])

# 3. 核心逻辑：如果用户上传了文件，就读取并展示
if uploaded_file is not None:
    # 根据文件后缀名判断读取方式
    if uploaded_file.name.endswith('.csv'):
        df = pd.read_csv(uploaded_file)
    elif uploaded_file.name.endswith('.json'):
        df = pd.read_json(uploaded_file, lines=True)
    else:
        st.error("暂不支持该文件格式，请上传 CSV 或 JSON。")
        st.stop()

    # --- 智能列名识别与用户强制兜底 ---
    def get_standard_columns(dataframe):
        # 预设的别名表（加入了流量字节相关的列）
        mapping = {
            'Label': ['Label', 'label', 'Class', 'class', 'Attack Type', 'attack_type', 'target', 'Attack', '攻击类型', '类别'],
            'Port Number': ['Port Number', 'port', 'Port', 'dst_port', 'Destination Port', 'destination_port', 'port_no', '端口', '端口号'],
            'Received Bytes': ['Received Bytes', 'received_bytes', 'recv_bytes', 'bytes_in', 'in_bytes', '接收字节', '接收字节数'],
            'Sent Bytes': ['Sent Bytes', 'sent_bytes', 'send_bytes', 'bytes_out', 'out_bytes', '发送字节', '发送字节数']
        }
        identified = {}
        for standard_name, aliases in mapping.items():
            for alias in aliases:
                if alias in dataframe.columns:
                    identified[standard_name] = alias
                    break
        missing = [std for std in mapping.keys() if std not in identified]
        return identified, missing

    identified_cols, missing_cols = get_standard_columns(df)

    with st.sidebar.expander("⚙️ 列名映射设置", expanded=bool(missing_cols)):
        # 攻击类型列
        if 'Label' in identified_cols:
            st.write(f"✅ 已自动识别攻击类型列：`{identified_cols['Label']}`")
        else:
            st.warning("未能自动识别【攻击类型】列，请手动选择：")
            user_label = st.selectbox("选择攻击类型列：", options=df.columns.tolist(), key="user_label")
            identified_cols['Label'] = user_label

        # 端口列
        if 'Port Number' in identified_cols:
            st.write(f"✅ 已自动识别端口列：`{identified_cols['Port Number']}`")
        else:
            st.warning("未能自动识别【端口号】列，请手动选择：")
            user_port = st.selectbox("选择端口列：", options=df.columns.tolist(), key="user_port")
            identified_cols['Port Number'] = user_port

        # 流量字节列兜底
        if 'Received Bytes' in identified_cols:
            st.write(f"✅ 已自动识别接收字节列：`{identified_cols['Received Bytes']}`")
        else:
            st.warning("未能自动识别【接收字节】列，请手动选择：")
            user_recv = st.selectbox("选择接收字节列：", options=df.columns.tolist(), key="user_recv")
            identified_cols['Received Bytes'] = user_recv

        if 'Sent Bytes' in identified_cols:
            st.write(f"✅ 已自动识别发送字节列：`{identified_cols['Sent Bytes']}`")
        else:
            st.warning("未能自动识别【发送字节】列，请手动选择：")
            user_sent = st.selectbox("选择发送字节列：", options=df.columns.tolist(), key="user_sent")
            identified_cols['Sent Bytes'] = user_sent

    # 根据最终确定的列名，对数据进行重命名（统一格式）
    rename_dict = {}
    for std_name, actual_name in identified_cols.items():
        if std_name != actual_name:
            rename_dict[actual_name] = std_name
            
    if rename_dict:
        df = df.rename(columns=rename_dict)
        st.sidebar.success(f"✅ 已完成列名映射。")
    
    # --- 侧边栏筛选器 ---
    if 'Label' in df.columns:
        unique_labels = df['Label'].unique().tolist()
        selected_labels = st.sidebar.multiselect(
            "请选择要分析的攻击类型：",
            options=unique_labels,
            default=unique_labels
        )
        if not selected_labels:
            st.warning("请在左侧至少选择一种攻击类型以显示图表。")
            df_filtered = df.iloc[0:0]
        else:
            df_filtered = df[df['Label'].isin(selected_labels)]
    else:
        st.warning("数据集中没有找到 'Label' 列，无法进行筛选和统计。")
        df_filtered = df
    
    # --- 数据预览 ---
    st.subheader("📋 数据预览")
    st.dataframe(df.head())

    # --- 彩色全局统计面板 ---
    st.subheader("📊 全局数据概览")
    total_records = len(df)
    total_types = df['Label'].nunique() if 'Label' in df.columns else 0
    if 'Label' in df.columns:
        attack_count = len(df[df['Label'] != 'Normal'])
        attack_ratio = (attack_count / len(df)) * 100
    else:
        attack_ratio = 0

    html_code = f"""
    <div style="display: flex; justify-content: space-between; gap: 20px;">
        <div style="flex: 1; background-color: #e8f5e9; border-left: 6px solid #4caf50; padding: 20px; border-radius: 8px; box-shadow: 2px 2px 10px rgba(0,0,0,0.1);">
            <p style="margin: 0; color: #2e7d32; font-size: 16px; font-weight: bold;">📋 总日志条数</p>
            <h2 style="margin: 10px 0 0 0; color: #1b5e20; font-size: 32px;">{total_records:,} 条</h2>
        </div>
        <div style="flex: 1; background-color: #e3f2fd; border-left: 6px solid #2196f3; padding: 20px; border-radius: 8px; box-shadow: 2px 2px 10px rgba(0,0,0,0.1);">
            <p style="margin: 0; color: #1565c0; font-size: 16px; font-weight: bold;">🦠 攻击类型总数</p>
            <h2 style="margin: 10px 0 0 0; color: #0d47a1; font-size: 32px;">{total_types} 种</h2>
        </div>
        <div style="flex: 1; background-color: #fff3e0; border-left: 6px solid #ff9800; padding: 20px; border-radius: 8px; box-shadow: 2px 2px 10px rgba(0,0,0,0.1);">
            <p style="margin: 0; color: #ef6c00; font-size: 16px; font-weight: bold;">⚠️ 异常流量占比</p>
            <h2 style="margin: 10px 0 0 0; color: #e65100; font-size: 32px;">{attack_ratio:.2f}%</h2>
        </div>
    </div>
    """
    st.html(html_code)

    # --- 攻击类型分布与统计 ---
    if 'Label' in df.columns:
        st.subheader("📊 攻击类型分布")
        attack_counts = df_filtered['Label'].value_counts().reset_index()
        attack_counts.columns = ['攻击类型', '次数']
        
        if not attack_counts.empty:
            # 环形图
            fig = px.pie(attack_counts, names='攻击类型', values='次数', title='日志攻击类型占比', hole=0.3)
            st.plotly_chart(fig, use_container_width=True)
            
            # 柱状图
            st.subheader("📈 攻击次数统计")
            fig_bar = px.bar(attack_counts, x='攻击类型', y='次数', title='各类攻击发生次数', color='攻击类型')
            st.plotly_chart(fig_bar, use_container_width=True)
            
            # --- 端口 TOP 10 排行 ---
            if 'Port Number' in df.columns:
                st.subheader("🔌 攻击源端口 TOP 10")
                port_counts = df['Port Number'].value_counts().head(10).reset_index()
                port_counts.columns = ['端口号', '攻击次数']
                fig_port = px.bar(port_counts, x='攻击次数', y='端口号', orientation='h', 
                                  title='被攻击次数最多的前10个端口', color='攻击次数', color_continuous_scale='Reds')
                st.plotly_chart(fig_port, use_container_width=True)
            
            # --- 流量大小对比分析折线图 ---
            if 'Received Bytes' in df.columns and 'Sent Bytes' in df.columns:
                st.subheader("📉 流量大小对比分析")
                # 取前 100 条记录，并重置索引
                df_line = df.head(100).reset_index()
                
                # 构造 melt 的 id_vars，只保留存在的列
                id_vars_list = ['index']
                if 'Label' in df_line.columns:
                    id_vars_list.append('Label')
                
                df_melted = df_line.melt(
                    id_vars=id_vars_list,
                    value_vars=['Received Bytes', 'Sent Bytes'],
                    var_name='流量方向',
                    value_name='字节数'
                )
                
                fig_line = px.line(
                    df_melted, x='index', y='字节数', color='流量方向', line_dash='流量方向',
                    title='前100条日志的流量字节数变化',
                    labels={'index': '日志序号', '字节数': '流量大小 (Bytes)'}
                )
                st.plotly_chart(fig_line, use_container_width=True)
        else:
            st.info("当前选择没有符合的数据，请调整筛选条件。")
    else:
        st.warning("数据集中没有找到 'Label' 列,请检查你的CSV文件列名是否为 Label。")

else:
    # 欢迎界面
    st.markdown("""
    ### 👋 欢迎使用网络安全日志分析平台
    
    本系统可以帮助你快速分析网络安全日志，洞察攻击趋势。请从左侧上传日志文件开始。
    
    **你可以上传的格式：**
    - CSV 格式的网络日志
    - JSON 格式的网络日志
    
    **上传后你能获得：**
    - 📊 全局数据概览（总条数、攻击类型数、异常占比）
    - 🥧 攻击类型分布环形图
    - 📈 攻击次数统计柱状图
    - 🔌 端口 TOP 10 排行
    - 📉 流量大小对比分析折线图
    """)
    st.info("👈 请从左侧侧边栏点击 'Browse files' 上传你的日志文件。")