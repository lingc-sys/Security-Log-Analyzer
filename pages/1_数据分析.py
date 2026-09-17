import streamlit as st
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="数据分析", layout="wide", initial_sidebar_state="expanded")

# ================= 1. 初始化会话状态 =================
if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'view_mode' not in st.session_state:
    st.session_state['view_mode'] = 'normal'

# ================= 2. 侧边栏：文件上传 =================
st.sidebar.header("数据管理")
if st.session_state['df'] is None:
    uploaded_file = st.sidebar.file_uploader("请上传日志文件 (CSV 或 JSON)", type=["csv", "json"])
    if uploaded_file is not None:
        if uploaded_file.name.endswith('.csv'):
            df_temp = pd.read_csv(uploaded_file)
        elif uploaded_file.name.endswith('.json'):
            df_temp = pd.read_json(uploaded_file, lines=True)
        else:
            st.sidebar.error("暂不支持该文件格式。")
            st.stop()
            
        def get_standard_columns(dataframe):
            mapping = {
                'Label': ['Label', 'label', 'Class', 'class', 'Attack Type', '攻击类型'],
                'Port Number': ['Port Number', 'port', 'Port', 'dst_port', '端口'],
                'Received Bytes': ['Received Bytes', 'recv_bytes', '接收字节'],
                'Sent Bytes': ['Sent Bytes', 'sent_bytes', '发送字节']
            }
            identified = {}
            for std_name, aliases in mapping.items():
                for alias in aliases:
                    if alias in dataframe.columns:
                        identified[std_name] = alias
                        break
            return identified, [std for std in mapping.keys() if std not in identified]

        identified_cols, _ = get_standard_columns(df_temp)
        rename_dict = {actual: std for std, actual in identified_cols.items() if std != actual}
        if rename_dict:
            df_temp = df_temp.rename(columns=rename_dict)
            
        st.session_state['df'] = df_temp
        st.sidebar.success("✅ 数据加载并完成列名映射！")
        st.rerun()
else:
    st.sidebar.success("✅ 数据已加载")
    if st.sidebar.button("重新上传数据"):
        st.session_state['df'] = None
        st.session_state['view_mode'] = 'normal'
        st.rerun()

# ================= 3. 数据筛选 =================
df = st.session_state['df']
if df is not None:
    if 'Label' in df.columns:
        unique_labels = df['Label'].unique().tolist()
        selected_labels = st.sidebar.multiselect("请选择要分析的攻击类型：", options=unique_labels, default=unique_labels)
        df_filtered = df[df['Label'].isin(selected_labels)] if selected_labels else df.iloc[0:0]
    else:
        df_filtered = df

    # ================= 4. 视图切换按钮 =================
    col_btn, col_empty = st.columns([1.5, 5])
    with col_btn:
        if st.session_state['view_mode'] == 'normal':
            if st.button("一键开启数据大屏", use_container_width=True, type="primary"):
                st.session_state['view_mode'] = 'dashboard'
                st.rerun()
        else:
            if st.button("⬅返回常规视图", use_container_width=True):
                st.session_state['view_mode'] = 'normal'
                st.rerun()

    # ================= 5. 渲染视图 =================
    if st.session_state['view_mode'] == 'normal':
        # ---------------- 【常规模式：原汁原味】 ----------------
        st.title("🛡️ 网络安全日志分析与可视化平台")
        st.subheader("数据预览")
        st.dataframe(df.head())
        
        total_records = len(df)
        total_types = df['Label'].nunique() if 'Label' in df.columns else 0
        attack_ratio = (len(df[df['Label'] != 'Normal']) / len(df) * 100) if 'Label' in df.columns else 0
        
        st.html(f"""
        <div style="display: flex; justify-content: space-between; gap: 20px; margin-top: 10px; margin-bottom: 20px;">
            <div style="flex: 1; background-color: #e8f5e9; border-left: 6px solid #4caf50; padding: 20px; border-radius: 8px; box-shadow: 2px 2px 10px rgba(0,0,0,0.1);">
                <p style="margin: 0; color: #2e7d32; font-size: 16px; font-weight: bold;">总日志条数</p>
                <h2 style="margin: 10px 0 0 0; color: #1b5e20; font-size: 32px;">{total_records:,} 条</h2>
            </div>
            <div style="flex: 1; background-color: #e3f2fd; border-left: 6px solid #2196f3; padding: 20px; border-radius: 8px; box-shadow: 2px 2px 10px rgba(0,0,0,0.1);">
                <p style="margin: 0; color: #1565c0; font-size: 16px; font-weight: bold;">攻击类型总数</p>
                <h2 style="margin: 10px 0 0 0; color: #0d47a1; font-size: 32px;">{total_types} 种</h2>
            </div>
            <div style="flex: 1; background-color: #fff3e0; border-left: 6px solid #ff9800; padding: 20px; border-radius: 8px; box-shadow: 2px 2px 10px rgba(0,0,0,0.1);">
                <p style="margin: 0; color: #ef6c00; font-size: 16px; font-weight: bold;">异常流量占比</p>
                <h2 style="margin: 10px 0 0 0; color: #e65100; font-size: 32px;">{attack_ratio:.2f}%</h2>
            </div>
        </div>
        """)
        
        if 'Label' in df.columns:
            attack_counts = df_filtered['Label'].value_counts().reset_index()
            attack_counts.columns = ['攻击类型', '次数']
            st.subheader("攻击类型分布")
            st.plotly_chart(px.pie(attack_counts, names='攻击类型', values='次数', hole=0.3), use_container_width=True)
            st.plotly_chart(px.bar(attack_counts, x='攻击类型', y='次数', color='攻击类型'), use_container_width=True)
            
    else:
        # ================= 【大屏模式：纯白背景 2行3列布局】 =================
        st.markdown("<h3 style='text-align: center; color: #1e293b; margin-bottom: 20px;'>网络安全日志智能监控大屏</h3>", unsafe_allow_html=True)

        # 1. 顶部指标卡片
        total_records = len(df)
        total_types = df['Label'].nunique() if 'Label' in df.columns else 0
        attack_ratio = (len(df[df['Label'] != 'Normal']) / len(df) * 100) if 'Label' in df.columns else 0
        
        col_m1, col_m2, col_m3 = st.columns(3)
        col_m1.metric("总日志条数", f"{total_records:,} 条")
        col_m2.metric("攻击类型总数", f"{total_types} 种")
        col_m3.metric("异常流量占比", f"{attack_ratio:.2f}%")

        st.markdown("<br>", unsafe_allow_html=True)

        # ================= 第一行：3个图表 =================
        row1_col1, row1_col2, row1_col3 = st.columns([1, 1.5, 1], gap="medium") # 中间列稍宽，突出核心折线图

        with row1_col1:
            st.markdown("#### 攻击类型分布")
            if 'Label' in df.columns:
                attack_counts = df_filtered['Label'].value_counts().reset_index()
                attack_counts.columns = ['攻击类型', '次数']
                fig_pie = px.pie(attack_counts, names='攻击类型', values='次数', hole=0.4, template="plotly_white")
                fig_pie.update_layout(margin=dict(t=10, b=10), height=300)
                st.plotly_chart(fig_pie, use_container_width=True)

        with row1_col2:
            st.markdown("#### 流量大小对比趋势（核心）")
            if 'Received Bytes' in df.columns and 'Sent Bytes' in df.columns:
                df_line = df.head(100).reset_index()
                id_vars_list = ['index'] + (['Label'] if 'Label' in df_line.columns else [])
                df_melted = df_line.melt(id_vars=id_vars_list, value_vars=['Received Bytes', 'Sent Bytes'], 
                                         var_name='流量方向', value_name='字节数')
                fig_line = px.line(df_melted, x='index', y='字节数', color='流量方向', 
                                   template="plotly_white", color_discrete_sequence=['#3b82f6', '#f59e0b'])
                fig_line.update_layout(margin=dict(t=10, b=10), height=300)
                st.plotly_chart(fig_line, use_container_width=True)

        with row1_col3:
            st.markdown("#### 攻击次数统计")
            if 'Label' in df.columns:
                attack_counts = df_filtered['Label'].value_counts().reset_index()
                attack_counts.columns = ['攻击类型', '次数']
                fig_bar = px.bar(attack_counts, x='攻击类型', y='次数', template="plotly_white", 
                                 color='攻击类型', color_discrete_sequence=px.colors.qualitative.Set2)
                fig_bar.update_layout(margin=dict(t=10, b=10), height=300, xaxis_tickangle=-45) # 标签倾斜，防重叠
                st.plotly_chart(fig_bar, use_container_width=True)

        st.markdown("<br>", unsafe_allow_html=True) # 行间距

        # ================= 第二行：1个图占1/3，数据预览占2/3 =================
        row2_col1, row2_col2 = st.columns([1, 2], gap="medium")

        with row2_col1:
            st.markdown("#### 🔌 攻击源端口 TOP 10")
            if 'Port Number' in df.columns:
                port_counts = df['Port Number'].value_counts().head(10).reset_index()
                port_counts.columns = ['端口号', '攻击次数']
                fig_port = px.bar(port_counts, x='攻击次数', y='端口号', orientation='h', 
                                  template="plotly_white", color_discrete_sequence=['#3b82f6'])
                fig_port.update_layout(margin=dict(t=10, b=10), height=350)
                st.plotly_chart(fig_port, use_container_width=True)

        with row2_col2:
            st.markdown("#### 数据采样预览")
            # 数据预览自然占2/3宽，使用 use_container_width=True 填满
            st.dataframe(df.head(10), use_container_width=True, height=350)

else:
    st.title("🛡️ 网络安全日志分析与可视化平台")
    st.info("👈 请从左侧侧边栏上传日志文件开始分析。")