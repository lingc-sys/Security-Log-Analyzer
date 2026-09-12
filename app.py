import streamlit as st
import pandas as pd
import plotly.express as px

# 1. 页面设置（保持原样，不用改）
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
    
    # --- 新增功能：侧边栏筛选器 ---
    # 从数据中获取所有唯一的攻击类型，去重后作为筛选选项
    if 'Label' in df.columns:
        unique_labels = df['Label'].unique().tolist()
        
        # 在侧边栏添加多选框
        selected_labels = st.sidebar.multiselect(
            "请选择要分析的攻击类型：",
            options=unique_labels,
            default=unique_labels  # 默认全选
        )
        
        # 根据用户的选择过滤数据
        if not selected_labels:
            st.warning("请在左侧至少选择一种攻击类型以显示图表。")
            df_filtered = df.iloc[0:0]  # 创建一个空数据集，让下面图表不显示
        else:
            df_filtered = df[df['Label'].isin(selected_labels)]
    else:
        st.warning("数据集中没有找到 'Label' 列，无法进行筛选和统计。")
        df_filtered = df  # 没有Label列就直接用原始数据
    
    # --- 以下是展示部分 ---
    
    # 在页面上展示数据预览（前5行）
    st.subheader("📋 数据预览")
    st.dataframe(df.head())
    
    # 检查是否存在名为 'Label' 的列，如果存在才画图
    if 'Label' in df.columns:
        st.subheader("📊 攻击类型分布")
        
        # 统计过滤后的 Label 列的数量
        attack_counts = df_filtered['Label'].value_counts().reset_index()
        attack_counts.columns = ['攻击类型', '次数']
        
        if not attack_counts.empty:
            # 画一个饼图（环形图）
            fig = px.pie(attack_counts, names='攻击类型', values='次数', 
                         title='日志攻击类型占比', hole=0.3)
            st.plotly_chart(fig, use_container_width=True)
            
            # 额外加一个柱状图
            st.subheader("📈 攻击次数统计")
            fig_bar = px.bar(attack_counts, x='攻击类型', y='次数', 
                             title='各类攻击发生次数', color='攻击类型')
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("当前选择没有符合的数据，请调整筛选条件。")
    else:
        st.warning("数据集中没有找到 'Label' 列,请检查你的CSV文件列名是否为 Label。")

else:
    st.info("👈 请从左侧侧边栏上传文件开始分析。")