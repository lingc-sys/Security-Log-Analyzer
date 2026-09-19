import streamlit as st
import pandas as pd
import numpy as np
import re

st.set_page_config(page_title="数据清洗与校验", layout="wide")

# =========================================================
# 模块一：数据清洗函数库（逻辑模块化）
# =========================================================

def remove_duplicates(df):
    """删除完全重复的行"""
    before = len(df)
    df = df.drop_duplicates()
    after = len(df)
    removed = before - after
    msg = f"去重：删除了 {removed} 行重复数据（剩余 {after} 行）"
    return df, msg

def handle_missing(df, strategy="drop"):
    """处理缺失值（默认删除含空值的行）"""
    before = df.isnull().sum().sum()
    if before == 0:
        return df, "✅ 缺失值处理：未发现空值，无需处理"
    if strategy == "drop":
        df = df.dropna()
    elif strategy == "fill_zero":
        df = df.fillna(0)
    msg = f"缺失值处理：发现 {before} 个空值，已处理（策略：{strategy}）"
    return df, msg

def normalize_labels(df):
    """规整攻击标签（统一大小写与拼写）"""
    if 'Label' not in df.columns:
        return df, "标签规整：未找到 Label 列，跳过"
    
    alias_map = {
        'portscan': 'PortScan', 'port scan': 'PortScan', 'portscanner': 'PortScan',
        'tcp-syn': 'TCP-SYN', 'tcp syn': 'TCP-SYN', 'tcpsyn': 'TCP-SYN',
        'blackhole': 'Blackhole', 'black hole': 'Blackhole',
        'diversion': 'Diversion', 'normal': 'Normal', 'overflow': 'Overflow'
    }
    before_values = df['Label'].astype(str).unique()
    
    def _normalize(val):
        v = str(val).strip().lower()
        return alias_map.get(v, str(val).strip())
    
    df['Label'] = df['Label'].apply(_normalize)
    after_values = df['Label'].unique()
    msg = f"标签规整：原有 {len(before_values)} 种标签，规整后 {len(after_values)} 种"
    return df, msg

def validate_port_range(df):
    """校验端口号：必须在 0-65535 之间"""
    if 'Port Number' not in df.columns:
        return df, "端口校验：未找到 Port Number 列，跳过"
    
    def _extract_port(val):
        nums = re.findall(r'\d+', str(val))
        return int(nums[0]) if nums else None
    
    df['Port Number'] = df['Port Number'].apply(_extract_port)
    invalid_mask = (df['Port Number'] < 0) | (df['Port Number'] > 65535) | (df['Port Number'].isnull())
    invalid_count = invalid_mask.sum()
    df.loc[invalid_mask, 'Port Number'] = pd.NA
    msg = f"🔢 端口校验：发现 {invalid_count} 个非法端口，已标记为缺失"
    return df, msg

# =========================================================
# 模块二：清洗流水线调度器
# =========================================================

def run_pipeline(df, operations):
    """按顺序执行清洗流水线"""
    report = []
    cleaned_df = df.copy()
    
    if "remove_duplicates" in operations:
        cleaned_df, msg = remove_duplicates(cleaned_df)
        report.append(msg)
    if "handle_missing" in operations:
        cleaned_df, msg = handle_missing(cleaned_df, strategy="drop")
        report.append(msg)
    if "normalize_labels" in operations:
        cleaned_df, msg = normalize_labels(cleaned_df)
        report.append(msg)
    if "validate_port_range" in operations:
        cleaned_df, msg = validate_port_range(cleaned_df)
        report.append(msg)
        
    return cleaned_df, report

# =========================================================
# 模块三：清洗报告生成器
# =========================================================

def generate_report(report_list, original_rows, cleaned_rows):
    retention = (cleaned_rows / original_rows * 100) if original_rows > 0 else 0
    items_html = "".join([f"<li style='margin: 8px 0;'>{item}</li>" for item in report_list])
    return f"""
    <div style="background-color: #f8fafc; border-left: 6px solid #3b82f6; 
                padding: 20px; border-radius: 8px; margin-top: 15px;
                box-shadow: 2px 2px 10px rgba(0,0,0,0.05);">
        <h4 style="margin: 0 0 12px 0; color: #1e293b;">🧾 清洗报告</h4>
        <p style="margin: 4px 0; color: #64748b;">
            原始数据：<b>{original_rows:,}</b> 行 &nbsp;→&nbsp; 
            清洗后：<b>{cleaned_rows:,}</b> 行 &nbsp;|&nbsp; 
            保留率：<b style="color: #16a34a;">{retention:.1f}%</b>
        </p>
        <ul style="margin: 12px 0 0 0; padding-left: 20px; color: #334155;">
            {items_html}
        </ul>
    </div>
    """

# =========================================================
# 模块四：页面渲染层（UI）
# =========================================================

st.title("🧹 数据清洗与校验工作台")
st.markdown("上传日志文件，一键执行标准化清洗流程。")

# 初始化状态
if 'clean_df' not in st.session_state:
    st.session_state['clean_df'] = None

# 侧边栏
st.sidebar.header("数据管理")
uploaded_file = st.sidebar.file_uploader("请上传日志文件 (CSV 或 JSON)", type=["csv", "json"])

st.sidebar.header("清洗配置")
st.sidebar.markdown("默认执行一键全流程清洗：\n- 去除重复行\n- 处理缺失值\n- 规整攻击标签\n- 校验端口范围")

if st.sidebar.button("开始一键清洗", use_container_width=True, type="primary"):
    st.session_state['do_clean'] = True

# 主逻辑
if uploaded_file is not None:
    # 读取数据（每次上传时重新加载）
    if st.session_state['clean_df'] is None or st.sidebar.button("🔄 重新上传数据"):
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        elif uploaded_file.name.endswith('.json'):
            df = pd.read_json(uploaded_file, lines=True)
        else:
            st.error("暂不支持该文件格式。")
            st.stop()
        st.session_state['clean_df'] = df

    df = st.session_state['clean_df']

    st.subheader("原始数据预览")
    st.dataframe(df.head(10), use_container_width=True)

    if st.session_state.get('do_clean', False):
        original_rows = len(df)
        operations = ["remove_duplicates", "handle_missing", "normalize_labels", "validate_port_range"]
        cleaned_df, report_list = run_pipeline(df, operations)
        cleaned_rows = len(cleaned_df)

        st.subheader("清洗结果")
        st.html(generate_report(report_list, original_rows, cleaned_rows))

        st.subheader("清洗后数据预览")
        st.dataframe(cleaned_df.head(10), use_container_width=True)

        # 下载按钮
        csv_data = cleaned_df.to_csv(index=False).encode('utf-8-sig')
        st.download_button(
            label="⬇️ 下载清洗后的数据 (CSV)",
            data=csv_data,
            file_name="cleaned_log.csv",
            mime="text/csv",
            use_container_width=True
        )
    else:
        st.info("👈 请点击左侧侧边栏的「开始一键清洗」按钮执行清洗。")

else:
    st.markdown("""
    ### 👋 欢迎使用数据清洗与校验工作台
    本模块支持对上传的网络安全日志进行标准化清洗：
    - **去除重复行**：删除完全重复的记录
    - **处理缺失值**：清理含空值的行
    - **规整攻击标签**：统一大小写与拼写差异
    - **校验端口范围**：过滤非法端口（0-65535）
    请从左侧上传日志文件开始。
    """)
    st.info("👈 请从左侧侧边栏点击 'Browse files' 上传你的日志文件。")