import streamlit as st
import pandas as pd
import plotly.express as px

# 1. 设置网页标题和布局
st.set_page_config(page_title="安全日志分析平台", layout="wide")
st.title("🛡️ 网络安全日志分析与可视化平台")
st.markdown("上传你的网络日志，快速洞察攻击趋势。")

# 2. 侧边栏：文件上传
st.sidebar.header("数据管理")
uploaded_file = st.sidebar.file_uploader("请上传CSV格式的日志文件", type=["csv"])

# 3. 核心逻辑：如果用户上传了文件，就读取并展示
if uploaded_file is not None:
    # 读取数据
    df = pd.read_csv(uploaded_file)
    
    # 在页面上展示数据预览（前5行）
    st.subheader("📋 数据预览")
    st.dataframe(df.head())
    
    # 检查是否存在名为 'Label' 的列
    if 'Label' in df.columns:
        st.subheader("📊 攻击类型分布")
        
        # 统计 Label 列的数量
        attack_counts = df['Label'].value_counts().reset_index()
        # 重命名列名，方便画图
        attack_counts.columns = ['攻击类型', '次数']
        
        # 画一个饼图
        fig = px.pie(attack_counts, names='攻击类型', values='次数', 
                     title='日志攻击类型占比', hole=0.3) # 加上hole变成环形图，更好看
        st.plotly_chart(fig, use_container_width=True)
        
        # 额外加一个柱状图，展示 Top 攻击
        st.subheader("📈 攻击次数统计")
        fig_bar = px.bar(attack_counts, x='攻击类型', y='次数', 
                         title='各类攻击发生次数', color='攻击类型')
        st.plotly_chart(fig_bar, use_container_width=True)
        
    else:
        st.warning("数据集中没有找到 'Label' 列，请检查你的CSV文件列名是否为 Label。")
else:
    st.info("👈 请从左侧侧边栏上传CSV文件开始分析。")