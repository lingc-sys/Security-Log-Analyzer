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
        st.session_state['df'] = df_temp
        st.sidebar.success("数据加载成功，请检查左侧列名映射。")
        st.rerun()
else:
    st.sidebar.success("数据已加载")
    if st.sidebar.button("重新上传数据"):
        st.session_state['df'] = None
        st.session_state['view_mode'] = 'normal'
        st.rerun()

# ================= 3. 智能列名识别 + 用户兜底 =================
df = st.session_state['df']

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

    if missing_cols:
        with st.sidebar.expander("手动列名映射设置", expanded=True):
            st.warning(f"未能自动识别以下关键列，请手动指定：{', '.join(missing_cols)}")
            if 'Label' in missing_cols:
                user_label = st.selectbox("请选择【攻击类型】所在的列名：", options=df.columns.tolist(), key="user_label")
                identified_cols['Label'] = user_label
            if 'Port Number' in missing_cols:
                user_port = st.selectbox("请选择【端口号】所在的列名：", options=df.columns.tolist(), key="user_port")
                identified_cols['Port Number'] = user_port
            if 'Received Bytes' in missing_cols:
                user_recv = st.selectbox("请选择【接收字节】所在的列名：", options=df.columns.tolist(), key="user_recv")
                identified_cols['Received Bytes'] = user_recv
            if 'Sent Bytes' in missing_cols:
                user_sent = st.selectbox("请选择【发送字节】所在的列名：", options=df.columns.tolist(), key="user_sent")
                identified_cols['Sent Bytes'] = user_sent

    rename_dict = {}
    for std_name, actual_name in identified_cols.items():
        if std_name != actual_name:
            rename_dict[actual_name] = std_name
    if rename_dict:
        df = df.rename(columns=rename_dict)
        st.session_state['df'] = df

    # ================= 4. 数据筛选 =================
    if 'Label' in df.columns:
        unique_labels = df['Label'].unique().tolist()
        selected_labels = st.sidebar.multiselect("请选择要分析的攻击类型：", options=unique_labels, default=unique_labels)
        df_filtered = df[df['Label'].isin(selected_labels)] if selected_labels else df.iloc[0:0]
    else:
        df_filtered = df

    # ================= 5. 视图切换 =================
    col_btn, col_empty = st.columns([1.5, 5])
    with col_btn:
        if st.session_state['view_mode'] == 'normal':
            if st.button("一键开启数据大屏", use_container_width=True, type="primary"):
                st.session_state['view_mode'] = 'dashboard'
                st.rerun()
        else:
            if st.button("返回常规视图", use_container_width=True):
                st.session_state['view_mode'] = 'normal'
                st.rerun()

    # ================= 6. 渲染视图 =================
    if st.session_state['view_mode'] == 'normal':
        # ---------------- 【常规模式】 ----------------
        st.title("网络安全日志分析与可视化平台")
        
        st.subheader("数据预览")
        st.dataframe(df.head())
        
        total_records = len(df)
        total_types = df['Label'].nunique() if 'Label' in df.columns else 0
        attack_ratio = (len(df[df['Label'] != 'Normal']) / len(df) * 100) if 'Label' in df.columns else 0
        
        if 'Label' in df.columns:
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
            col_pie, col_bar = st.columns(2)
            with col_pie:
                st.plotly_chart(px.pie(attack_counts, names='攻击类型', values='次数', hole=0.3, title='日志攻击类型占比'), use_container_width=True)
            with col_bar:
                st.plotly_chart(px.bar(attack_counts, x='攻击类型', y='次数', title='各类攻击发生次数', color='攻击类型'), use_container_width=True)
            
        if 'Port Number' in df.columns or ('Received Bytes' in df.columns and 'Sent Bytes' in df.columns and 'Label' in df.columns):
            st.markdown("---")
            col_port, col_flow = st.columns([1, 1.2], gap="medium")

            with col_port:
                if 'Port Number' in df.columns:
                    st.subheader("攻击源端口 TOP 10")
                    port_counts = df['Port Number'].value_counts().head(10).reset_index()
                    port_counts.columns = ['端口号', '攻击次数']
                    fig_port = px.bar(port_counts, x='攻击次数', y='端口号', orientation='h', template="plotly_white", color_discrete_sequence=['#3b82f6'])
                    fig_port.update_layout(margin=dict(t=10, b=10), height=400)
                    st.plotly_chart(fig_port, use_container_width=True)

            with col_flow:
                if 'Received Bytes' in df.columns and 'Sent Bytes' in df.columns and 'Label' in df.columns:
                    col_title, col_select = st.columns([1, 1])
                    with col_title:
                        st.subheader("流量趋势分析")
                    with col_select:
                        attack_labels = df['Label'].unique().tolist()
                        selected_attack = st.selectbox("选择攻击方式：", attack_labels, label_visibility="collapsed")
                    
                    df_selected = df[df['Label'] == selected_attack].head(100).reset_index()
                    if not df_selected.empty:
                        df_melted = df_selected.melt(id_vars=['index'], value_vars=['Received Bytes', 'Sent Bytes'], var_name='流量方向', value_name='字节数')
                        fig_line = px.line(df_melted, x='index', y='字节数', color='流量方向', line_dash='流量方向', template="plotly_white", color_discrete_sequence=['#3b82f6', '#f59e0b'])
                        fig_line.update_layout(margin=dict(t=10, b=10), height=400, showlegend=False)
                        st.plotly_chart(fig_line, use_container_width=True)
                    else:
                        st.info(f"当前攻击类型 [{selected_attack}] 没有足够的数据用于绘图。")

        numeric_df = df.select_dtypes(include=['number'])
        if len(numeric_df.columns) > 1:
            st.markdown("---")
            st.subheader("特征相关性热力图")
            numeric_df = numeric_df.iloc[:, :10]
            corr_matrix = numeric_df.corr()
            fig_heatmap = px.imshow(corr_matrix, text_auto=".2f", aspect="auto", color_continuous_scale='RdBu_r', title='网络流量特征相关性矩阵 (Pearson)', labels=dict(color="相关系数"))
            fig_heatmap.update_layout(height=600, margin=dict(t=50, b=50, l=50, r=50), xaxis_tickangle=-45)
            st.plotly_chart(fig_heatmap, use_container_width=True)

        if 'Received Bytes' in df.columns and 'Sent Bytes' in df.columns and 'Label' in df.columns:
            st.markdown("---")
            st.subheader("流量特征散点图 (多维聚类分析)")
            df_scatter = df_filtered.head(1000).copy()
            if not df_scatter.empty:
                size_arg = 'Received Packets' if 'Received Packets' in df_scatter.columns else None
                hover_arg = ['Port Number'] if 'Port Number' in df_scatter.columns else None
                fig_scatter = px.scatter(df_scatter, x='Received Bytes', y='Sent Bytes', color='Label', size=size_arg, hover_data=hover_arg, template="plotly_white", title="不同攻击类型的流量特征分布", opacity=0.7)
                fig_scatter.update_layout(height=500, margin=dict(t=40, b=20, l=20, r=20))
                st.plotly_chart(fig_scatter, use_container_width=True)

        if 'Received Bytes' in df.columns and 'Sent Bytes' in df.columns:
            try:
                from sklearn.ensemble import IsolationForest
                from sklearn.preprocessing import StandardScaler
                has_ml = True
            except ImportError:
                has_ml = False
                st.error("请先在终端安装机器学习库：pip install scikit-learn")

            if has_ml:
                feature_cols = [col for col in ['Received Bytes', 'Sent Bytes', 'Received Packets', 'Sent Packets', 'Port alive Duration (S)'] if col in df.columns]
                if len(feature_cols) >= 2:
                    st.markdown("---")
                    st.subheader("未知威胁预警 (基于孤立森林)")
                    df_ml = df[feature_cols].fillna(0).copy()
                    scaler = StandardScaler()
                    df_scaled = scaler.fit_transform(df_ml)
                    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
                    df['Anomaly_Score'] = model.fit_predict(df_scaled)
                    df['Anomaly_Raw_Score'] = model.decision_function(df_scaled)
                    anomaly_count = (df['Anomaly_Score'] == -1).sum()
                    col_m1, col_m2 = st.columns(2)
                    col_m1.metric("正常流量记录", f"{len(df) - anomaly_count:,} 条")
                    col_m2.metric("疑似未知威胁", f"{anomaly_count:,} 条", delta_color="inverse")
                    df_ml_plot = df.head(1000).copy()
                    df_ml_plot['状态'] = df_ml_plot['Anomaly_Score'].map({1: '正常', -1: '异常'})
                    fig_anomaly = px.scatter(df_ml_plot, x='Received Bytes', y='Sent Bytes', color='状态', color_discrete_map={'正常': '#94a3b8', '异常': '#ef4444'}, hover_data=['Label'] if 'Label' in df_ml_plot.columns else None, template="plotly_white", title="孤立森林异常点分布（红色为模型检测出的异常）")
                    fig_anomaly.update_layout(height=450, margin=dict(t=40, b=20, l=20, r=20))
                    st.plotly_chart(fig_anomaly, use_container_width=True)
                    st.markdown("最可疑的 10 条记录（按异常分数排序）：")
                    top_anomalies = df.nsmallest(10, 'Anomaly_Raw_Score')[[c for c in ['Label'] if c in df.columns] + feature_cols + ['Anomaly_Raw_Score']]
                    st.dataframe(top_anomalies, use_container_width=True)

    else:
        # ================= 【大屏模式：2行3列 + 下方独立两行】 =================
        st.markdown("<h3 style='text-align: center; color: #1e293b; margin-bottom: 10px;'>网络安全日志智能监控大屏</h3>", unsafe_allow_html=True)

                # 1. 顶部指标卡片（彩色方框）
        total_records = len(df)
        total_types = df['Label'].nunique() if 'Label' in df.columns else 0
        attack_ratio = (len(df[df['Label'] != 'Normal']) / len(df) * 100) if 'Label' in df.columns else 0
        
        st.html(f"""
        <div style="display: flex; justify-content: space-between; gap: 20px; margin-bottom: 20px;">
            <div style="flex: 1; background-color: #e8f5e9; border-left: 6px solid #4caf50; padding: 16px 20px; border-radius: 8px; box-shadow: 2px 2px 10px rgba(0,0,0,0.08);">
                <p style="margin: 0; color: #2e7d32; font-size: 15px; font-weight: bold;">📋 总日志条数</p>
                <h2 style="margin: 6px 0 0 0; color: #1b5e20; font-size: 28px;">{total_records:,} 条</h2>
            </div>
            <div style="flex: 1; background-color: #e3f2fd; border-left: 6px solid #2196f3; padding: 16px 20px; border-radius: 8px; box-shadow: 2px 2px 10px rgba(0,0,0,0.08);">
                <p style="margin: 0; color: #1565c0; font-size: 15px; font-weight: bold;">🦠 攻击类型总数</p>
                <h2 style="margin: 6px 0 0 0; color: #0d47a1; font-size: 28px;">{total_types} 种</h2>
            </div>
            <div style="flex: 1; background-color: #fff3e0; border-left: 6px solid #ff9800; padding: 16px 20px; border-radius: 8px; box-shadow: 2px 2px 10px rgba(0,0,0,0.08);">
                <p style="margin: 0; color: #ef6c00; font-size: 15px; font-weight: bold;">⚠️ 异常流量占比</p>
                <h2 style="margin: 6px 0 0 0; color: #e65100; font-size: 28px;">{attack_ratio:.2f}%</h2>
            </div>
        </div>
        """)

        # ================= 第一行 =================
        row1_col1, row1_col2, row1_col3 = st.columns([1, 1.5, 1], gap="medium")

        with row1_col1:
            st.markdown("**攻击类型分布**")
            if 'Label' in df.columns:
                attack_counts = df_filtered['Label'].value_counts().reset_index()
                attack_counts.columns = ['攻击类型', '次数']
                fig_pie = px.pie(attack_counts, names='攻击类型', values='次数', hole=0.4, template="plotly_white")
                fig_pie.update_layout(margin=dict(t=10, b=10), height=260)
                st.plotly_chart(fig_pie, use_container_width=True)
            else:
                st.info("缺少 Label 字段")

        with row1_col2:
            st.markdown("**流量大小对比趋势**")
            if 'Received Bytes' in df.columns and 'Sent Bytes' in df.columns:
                df_line = df.head(100).reset_index()
                id_vars_list = ['index'] + (['Label'] if 'Label' in df_line.columns else [])
                df_melted = df_line.melt(id_vars=id_vars_list, value_vars=['Received Bytes', 'Sent Bytes'], var_name='流量方向', value_name='字节数')
                fig_line = px.line(df_melted, x='index', y='字节数', color='流量方向', template="plotly_white", color_discrete_sequence=['#3b82f6', '#f59e0b'])
                fig_line.update_layout(margin=dict(t=10, b=10), height=260)
                st.plotly_chart(fig_line, use_container_width=True)
            else:
                st.info("缺少流量字节字段")

        with row1_col3:
            st.markdown("**攻击次数统计**")
            if 'Label' in df.columns:
                attack_counts = df_filtered['Label'].value_counts().reset_index()
                attack_counts.columns = ['攻击类型', '次数']
                fig_bar = px.bar(attack_counts, x='攻击类型', y='次数', template="plotly_white", color='攻击类型', color_discrete_sequence=px.colors.qualitative.Set2)
                fig_bar.update_layout(margin=dict(t=10, b=10), height=260, xaxis_tickangle=-45)
                st.plotly_chart(fig_bar, use_container_width=True)
            else:
                st.info("缺少 Label 字段")

        st.markdown("<br>", unsafe_allow_html=True)

        # ================= 第二行 =================
        row2_col1, row2_col2, row2_col3 = st.columns([1, 1.5, 1], gap="medium")

        with row2_col1:
            st.markdown("**攻击源端口TOP 10**")
            if 'Port Number' in df.columns:
                port_counts = df['Port Number'].value_counts().head(10).reset_index()
                port_counts.columns = ['端口号', '攻击次数']
                fig_port = px.bar(port_counts, x='攻击次数', y='端口号', orientation='h', template="plotly_white", color_discrete_sequence=['#3b82f6'])
                fig_port.update_layout(margin=dict(t=10, b=10), height=260)
                st.plotly_chart(fig_port, use_container_width=True)
            else:
                st.info("缺少 Port Number 字段")

        with row2_col2:
            st.markdown("**特征相关性热力图**")
            numeric_df = df.select_dtypes(include=['number'])
            if len(numeric_df.columns) > 1:
                numeric_df = numeric_df.iloc[:, :10]
                corr_matrix = numeric_df.corr()
                fig_heatmap = px.imshow(corr_matrix, text_auto=".2f", aspect="auto", color_continuous_scale='RdBu_r', template="plotly_white")
                fig_heatmap.update_layout(margin=dict(t=10, b=10), height=260, xaxis_tickangle=-45)
                st.plotly_chart(fig_heatmap, use_container_width=True)
            else:
                st.info("数值型特征不足两个")

        with row2_col3:
            st.markdown("**流量特征散点图**")
            if 'Received Bytes' in df.columns and 'Sent Bytes' in df.columns and 'Label' in df.columns:
                df_scatter = df_filtered.head(1000).copy()
                if not df_scatter.empty:
                    fig_scatter = px.scatter(df_scatter, x='Received Bytes', y='Sent Bytes', color='Label', template="plotly_white", opacity=0.7)
                    fig_scatter.update_layout(margin=dict(t=10, b=10), height=260)
                    st.plotly_chart(fig_scatter, use_container_width=True)
                else:
                    st.info("当前筛选条件无数据")
            else:
                st.info("缺少绘图所需字段")

        # ================= 第三行：孤立森林（整行铺满） =================
        st.markdown("---")
        st.markdown("**未知威胁预警 (基于孤立森林)**")
        if 'Received Bytes' in df.columns and 'Sent Bytes' in df.columns:
            try:
                from sklearn.ensemble import IsolationForest
                from sklearn.preprocessing import StandardScaler
                has_ml = True
            except ImportError:
                has_ml = False
                st.error("请先在终端安装机器学习库：pip install scikit-learn")

            if has_ml:
                feature_cols = [col for col in ['Received Bytes', 'Sent Bytes', 'Received Packets', 'Sent Packets', 'Port alive Duration (S)'] if col in df.columns]
                if len(feature_cols) >= 2:
                    df_ml = df[feature_cols].fillna(0).copy()
                    scaler = StandardScaler()
                    df_scaled = scaler.fit_transform(df_ml)
                    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
                    df['Anomaly_Score'] = model.fit_predict(df_scaled)
                    df['Anomaly_Raw_Score'] = model.decision_function(df_scaled)
                    anomaly_count = (df['Anomaly_Score'] == -1).sum()
                    col_m1, col_m2 = st.columns(2)
                    col_m1.metric("正常流量记录", f"{len(df) - anomaly_count:,} 条")
                    col_m2.metric("疑似未知威胁", f"{anomaly_count:,} 条", delta_color="inverse")
                    df_ml_plot = df.head(1000).copy()
                    df_ml_plot['状态'] = df_ml_plot['Anomaly_Score'].map({1: '正常', -1: '异常'})
                    fig_anomaly = px.scatter(df_ml_plot, x='Received Bytes', y='Sent Bytes', color='状态', color_discrete_map={'正常': '#94a3b8', '异常': '#ef4444'}, hover_data=['Label'] if 'Label' in df_ml_plot.columns else None, template="plotly_white")
                    fig_anomaly.update_layout(margin=dict(t=10, b=10), height=400)
                    st.plotly_chart(fig_anomaly, use_container_width=True)

                    # ================= 第四行：Top 10 可疑记录（整行铺满） =================
                    st.markdown("---")
                    st.markdown("**最可疑的 10 条记录(按异常分数降序)**")
                    top_anomalies = df.nsmallest(10, 'Anomaly_Raw_Score')[[c for c in ['Label'] if c in df.columns] + feature_cols + ['Anomaly_Raw_Score']]
                    st.dataframe(top_anomalies, use_container_width=True)

else:
    st.title("网络安全日志分析与可视化平台")
    st.markdown("请从左侧侧边栏上传日志文件开始分析。")
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    st.html("""
    <div style="background-color: #f0f5ff; border: 2px dashed #b3cfff; border-radius: 12px; padding: 30px 20px; margin-top: 10px;">
        
        <h4 style="text-align: center; color: #1e3a8a; margin-bottom: 30px; font-size: 20px;">
            标准规范与核心功能
        </h4>
        
        <div style="display: flex; justify-content: space-between; gap: 20px;">
            
            <!-- 卡片 1:数据标准 -->
            <div style="flex: 1; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
                <div style="background-color: #5b9bd5; color: white; text-align: center; padding: 12px 0; font-weight: bold; font-size: 15px;">
                    数据标准
                </div>
                <div style="background-color: white; padding: 22px 15px; text-align: center; color: #475569; font-size: 14px; line-height: 1.9;">
                    命名规范、数据字典<br>标准编码、标准文件
                </div>
            </div>

            <!-- 卡片 2:数据质量 -->
            <div style="flex: 1; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
                <div style="background-color: #5b9bd5; color: white; text-align: center; padding: 12px 0; font-weight: bold; font-size: 15px;">
                    数据质量
                </div>
                <div style="background-color: white; padding: 22px 15px; text-align: center; color: #475569; font-size: 14px; line-height: 1.9;">
                    数据清洗、标准转换<br>分类存储、质量映射
                </div>
            </div>

            <!-- 卡片 3:多维分析 -->
            <div style="flex: 1; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
                <div style="background-color: #5b9bd5; color: white; text-align: center; padding: 12px 0; font-weight: bold; font-size: 15px;">
                    多维分析
                </div>
                <div style="background-color: white; padding: 22px 15px; text-align: center; color: #475569; font-size: 14px; line-height: 1.9;">
                    攻击类型、端口、<br>流量趋势、相关性
                </div>
            </div>

            <!-- 卡片 4:智能预警 -->
            <div style="flex: 1; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
                <div style="background-color: #5b9bd5; color: white; text-align: center; padding: 12px 0; font-weight: bold; font-size: 15px;">
                    智能预警
                </div>
                <div style="background-color: white; padding: 22px 15px; text-align: center; color: #475569; font-size: 14px; line-height: 1.9;">
                    孤立森林异常检测<br>未知威胁预警
                </div>
            </div>

        </div>
    </div>
    """)
    
    st.markdown("<br>", unsafe_allow_html=True)
    st.info("请从左侧侧边栏点击 'Browse files' 上传你的日志文件。")

