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
            
        # 智能列名识别
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
            if st.button("⬅️ 返回常规视图", use_container_width=True):
                st.session_state['view_mode'] = 'normal'
                st.rerun()

    # ================= 5. 渲染视图 =================
    if st.session_state['view_mode'] == 'normal':
#常规模式
        st.title("网络安全日志分析与可视化平台")
        
# 1. 数据预览
        st.subheader("数据预览")
        st.dataframe(df.head())
        
        total_records = len(df)
        total_types = df['Label'].nunique() if 'Label' in df.columns else 0
        attack_ratio = (len(df[df['Label'] != 'Normal']) / len(df) * 100) if 'Label' in df.columns else 0
        
# 2. 全局指标卡片
        st.html(f"""
        <div style="display: flex; justify-content: space-between; gap: 20px; margin-top: 10px; margin-bottom: 20px;">
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
        """)
        
# 3. 攻击类型分布（环形图和柱状图并排）
        if 'Label' in df.columns:
            attack_counts = df_filtered['Label'].value_counts().reset_index()
            attack_counts.columns = ['攻击类型', '次数']
            
            st.subheader("攻击类型分布")
            col_pie, col_bar = st.columns(2)
            with col_pie:
                fig_pie = px.pie(attack_counts, names='攻击类型', values='次数', hole=0.3, title='日志攻击类型占比')
                st.plotly_chart(fig_pie, use_container_width=True)
            with col_bar:
                fig_bar = px.bar(attack_counts, x='攻击类型', y='次数', title='各类攻击发生次数', color='攻击类型')
                st.plotly_chart(fig_bar, use_container_width=True)
            
        # 4. 将端口排行和流量分析放在同一行
        st.markdown("---")
        col_port, col_flow = st.columns([1, 1.2], gap="medium") # 右侧流量图稍微宽一点

        # ---------------- 左侧：攻击源端口 TOP 10 ----------------
        with col_port:
            st.subheader("🔌 攻击源端口 TOP 10")
            if 'Port Number' in df.columns:
                port_counts = df['Port Number'].value_counts().head(10).reset_index()
                port_counts.columns = ['端口号', '攻击次数']
                fig_port = px.bar(port_counts, x='攻击次数', y='端口号', orientation='h', 
                                  template="plotly_white", color_discrete_sequence=['#3b82f6'])
                fig_port.update_layout(margin=dict(t=10, b=10), height=400)
                st.plotly_chart(fig_port, use_container_width=True)

        # ---------------- 右侧：基于攻击方式的流量折线图 ----------------
        with col_flow:
            # 把下拉框放在标题右侧，模拟“图例”的位置
            col_title, col_select = st.columns([1, 1])
            with col_title:
                st.subheader("流量趋势分析")
            with col_select:
                if 'Label' in df.columns:
                    # 获取所有唯一的攻击类型
                    attack_labels = df['Label'].unique().tolist()
                    # 下拉框，单次只能选择一种攻击方式
                    selected_attack = st.selectbox("选择攻击方式：", attack_labels, label_visibility="collapsed")
            
            # 根据用户选择的攻击方式，过滤数据
            if 'Label' in df.columns:
                df_selected = df[df['Label'] == selected_attack].head(100).reset_index()
                
                if not df_selected.empty:
                    # 构造 melt 数据，保留两条线（接收/发送）
                    id_vars_list = ['index']
                    df_melted = df_selected.melt(
                        id_vars=id_vars_list,
                        value_vars=['Received Bytes', 'Sent Bytes'],
                        var_name='流量方向',
                        value_name='字节数'
                    )
                    
                    # 画折线图，并隐藏图例（showlegend=False）
                    fig_line = px.line(
                        df_melted, x='index', y='字节数', color='流量方向', line_dash='流量方向',
                        template="plotly_white", color_discrete_sequence=['#3b82f6', '#f59e0b']
                    )
                    fig_line.update_layout(
                        margin=dict(t=10, b=10), 
                        height=400,
                        showlegend=False, # 隐藏自带的图例，因为我们已经用下拉菜单代替了
                        
                    )
                    st.plotly_chart(fig_line, use_container_width=True)
                else:
                    st.info(f"当前攻击类型 [{selected_attack}] 没有足够的数据用于绘图。")
            else:
                st.warning("数据集中没有找到 'Label' 列，无法进行流量趋势分析。")
# 6. 特征相关性热力图（新增）
        st.subheader("特征相关性热力图")
        
        # 只选取数值类型的列（排除掉 Label、Switch ID 等文本列）
        numeric_df = df.select_dtypes(include=['number'])
        
        # 为了图不那么拥挤，我们最多选取前 10 个数值列
        if len(numeric_df.columns) > 1:
            numeric_df = numeric_df.iloc[:, :10] # 取前10列
            
            # 计算相关系数矩阵
            corr_matrix = numeric_df.corr()
            
            # 绘制热力图
            fig_heatmap = px.imshow(
                corr_matrix,
                text_auto=".2f",          # 显示相关系数，保留两位小数
                aspect="auto",            # 自动适应宽高比
                color_continuous_scale='RdBu_r', # 红蓝配色（红正蓝负）
                title='网络流量特征相关性矩阵 (Pearson)',
                labels=dict(color="相关系数")
            )
            
            # 调整布局，防止横轴文字重叠
            fig_heatmap.update_layout(
                height=600,
                margin=dict(t=50, b=50, l=50, r=50),
                xaxis_tickangle=-45
            )
            
            st.plotly_chart(fig_heatmap, use_container_width=True)
        else:
            st.info("数据集中数值型特征不足两个，无法绘制相关性热力图。")
# 7. 流量特征散点图
        st.markdown("---")
        st.subheader("流量特征散点图 (多维聚类分析)")
        
        # 检查必须的字段是否存在
        if 'Received Bytes' in df.columns and 'Sent Bytes' in df.columns and 'Label' in df.columns:
            # 为了避免数据量过大导致浏览器卡顿，最多取 1000 个点
            df_scatter = df_filtered.head(1000).copy()
            
            if not df_scatter.empty:
                # 动态判断是否使用 size 参数（如果你的数据集有 Received Packets 这一列，点的大小会随之变化，更立体）
                size_arg = 'Received Packets' if 'Received Packets' in df_scatter.columns else None
                hover_arg = ['Port Number'] if 'Port Number' in df_scatter.columns else None

                fig_scatter = px.scatter(
                    df_scatter,
                    x='Received Bytes',
                    y='Sent Bytes',
                    color='Label',                # 按攻击类型着色
                    size=size_arg,                # 点的大小反映包的数量
                    hover_data=hover_arg,         # 鼠标悬停显示端口号
                    template="plotly_white",
                    title="不同攻击类型的流量特征分布",
                    opacity=0.7                   # 设置透明度，密集处能看清重叠情况
                )
                fig_scatter.update_layout(height=500, margin=dict(t=40, b=20, l=20, r=20))
                st.plotly_chart(fig_scatter, use_container_width=True)
            else:
                st.info("当前筛选条件下没有数据可供绘图。")
        else:
            st.warning("缺少绘图所需字段(Received Bytes、Sent Bytes 或 Label),无法绘制散点图。")
# 8. 基于孤立森林的未知威胁预警（调整状态）
        st.markdown("---")
        st.subheader("未知威胁预警 (基于孤立森林)")
        
        # 检查是否安装了 scikit-learn，并确认关键列存在
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
            has_ml = True
        except ImportError:
            has_ml = False
            st.error("请先在终端安装机器学习库：pip install scikit-learn")

        if has_ml and 'Received Bytes' in df.columns and 'Sent Bytes' in df.columns:
            # 动态选择数据集中存在的数值特征列
            feature_cols = []
            for col in ['Received Bytes', 'Sent Bytes', 'Received Packets', 'Sent Packets', 'Port alive Duration (S)']:
                if col in df.columns:
                    feature_cols.append(col)
            
            if len(feature_cols) >= 2:
                # 1. 准备数据：取出特征列，处理空值（用0填充）
                df_ml = df[feature_cols].fillna(0).copy()
                
                # 2. 数据标准化（让所有特征处于同一量级，避免大数值主导模型）
                scaler = StandardScaler()
                df_scaled = scaler.fit_transform(df_ml)
                
                # 3. 训练孤立森林模型
                # contamination=0.05 表示我们假设大约5%的数据是异常的
                model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
                df['Anomaly_Score'] = model.fit_predict(df_scaled)  # 1表示正常，-1表示异常
                df['Anomaly_Raw_Score'] = model.decision_function(df_scaled) # 分数越低越异常
                
                # 4. 统计异常数量
                anomaly_count = (df['Anomaly_Score'] == -1).sum()
                
                col_m1, col_m2 = st.columns(2)
                col_m1.metric("正常流量记录", f"{len(df) - anomaly_count:,} 条")
                col_m2.metric("疑似未知威胁", f"{anomaly_count:,} 条", delta_color="inverse")
                
                # 5. 将异常点可视化在散点图上
                df_ml_plot = df.head(1000).copy() # 取前1000条用于绘图
                df_ml_plot['状态'] = df_ml_plot['Anomaly_Score'].map({1: '正常', -1: '异常'})
                
                fig_anomaly = px.scatter(
                    df_ml_plot, 
                    x='Received Bytes', 
                    y='Sent Bytes', 
                    color='状态',
                    color_discrete_map={'正常': '#94a3b8', '异常': '#ef4444'}, # 正常灰色，异常红色
                    hover_data=['Label'], # 悬停显示它原本的标签（看看被误报的是不是真的是攻击）
                    template="plotly_white",
                    title="孤立森林异常点分布（红色为模型检测出的异常）"
                )
                fig_anomaly.update_layout(height=450, margin=dict(t=40, b=20, l=20, r=20))
                st.plotly_chart(fig_anomaly, use_container_width=True)
                
                # 6. 展示最异常的 Top 10 记录
                st.markdown("**🔍 最可疑的 10 条记录（按异常分数排序）：**")
                top_anomalies = df.nsmallest(10, 'Anomaly_Raw_Score')[['Label'] + feature_cols + ['Anomaly_Raw_Score']]
                st.dataframe(top_anomalies, use_container_width=True)
                
            else:
                st.info("数据集中数值型特征不足，无法训练异常检测模型。")
        elif has_ml:
            st.warning("缺少流量特征列，无法运行异常检测。")

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

        # 2. 第一行：3个图表
        row1_col1, row1_col2, row1_col3 = st.columns([1, 1.5, 1], gap="medium")

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
                fig_bar.update_layout(margin=dict(t=10, b=10), height=300, xaxis_tickangle=-45)
                st.plotly_chart(fig_bar, use_container_width=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # 3. 第二行：1个图占1/3，数据预览占2/3
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
            st.dataframe(df.head(10), use_container_width=True, height=350)

else:
    st.title("🛡️ 网络安全日志分析与可视化平台")
    st.info("👈 请从左侧侧边栏上传日志文件开始分析。")