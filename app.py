import streamlit as st

st.set_page_config(page_title="SecureViz 首页", layout="wide")

#1. 注入 CSS（背景图 + 卡片样式
st.markdown("""
<style>
/* 把 1rem 改成 2.5rem，让顶部多出约 40px 的呼吸空间 */
    .block-container {
        padding-top: 2.5rem !important; 
        margin-top: 0 !important;
    }

    /* 给大标题也加一点点上边距 */
    .main-title {
        margin-top: 10px !important; 
        margin-bottom: 20px !important;
        line-height: 1.4 !important; /* 加上行高，防止字体上下被裁切 */
    }
    /* 背景图层：固定不动，全屏覆盖，不压缩变形 */
    .bg-layer {
        position: fixed;
        top: 0; left: 0;
        width: 100vw; height: 100vh;
        /* 浅色清爽的数据科技背景图 */
        background-image: url('https://images.unsplash.com/photo-1551288049-bebda4e38f71?q=80&w=2070&auto=format&fit=crop');
        background-size: cover;       /*等比例缩放，填满屏幕，绝对不拉伸 */
        background-position: center;
        background-repeat: no-repeat;
        z-index: -9999;               /* 压在页面最底层 */
        opacity: 0.35;                /* 降低透明度，让背景很清爽，不干扰文字 */
    }
    
    /* 大标题样式 */
    .main-title {
        text-align: center;
        font-size: 42px;
        font-weight: 800;
        color: #1e293b;
        margin-top: 60px;
        margin-bottom: 10px;
        letter-spacing: 2px;
    }
    .sub-title {
        text-align: center;
        font-size: 16px;
        color: #64748b;
        margin-bottom: 50px;
    }

    /* 卡片样式 */
        .card {
        background-color: rgba(255, 255, 255, 0.95);
        border-radius: 12px;
        padding: 24px;
        min-height: 200px; /* 改成最小高度 */
        height: auto;      /* 高度自适应 */
        box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        transition: transform 0.3s, box-shadow 0.3s;
        border: 1px solid #f1f5f9;
        word-wrap: break-word; /* 加上防溢出断行 */
    }
    .card:hover {
        transform: translateY(-5px); /* 悬浮上浮效果 */
        box-shadow: 0 12px 24px rgba(0,0,0,0.1);
    }
    .card-number {
        font-size: 32px;
        font-weight: 900;
        color: #3b82f6; /* 亮蓝色 */
        margin-bottom: 10px;
    }
    .card-title {
        font-size: 18px;
        font-weight: bold;
        color: #1e293b;
        margin-bottom: 10px;
    }
    .card-desc {
        font-size: 13px;
        color: #64748b;
        line-height: 1.5;
    }
</style>
<div class="bg-layer"></div>
""", unsafe_allow_html=True)

# 2.渲染标题
st.markdown("<div class='main-title'>见远，让数据用起来</div>", unsafe_allow_html=True)
#展示区
# 4. 案例体验展示区
st.markdown("<br><br>", unsafe_allow_html=True) # 加一点间距
st.markdown("<h3 style='color: #1e293b;'>示范案例</h3>", unsafe_allow_html=True)
st.markdown("---")

# 分成四列
col_case1, col_case2, col_case3, col_case4 = st.columns(4, gap="medium")

#案例1
with col_case1:

    st.image("Picture/攻击次数.png", use_container_width=True)
    st.markdown("**攻击次数**")
    st.markdown("<div style='color: #64748b; font-size: 13px;'>直观展示 PortScan、TCP-SYN 等攻击的频次。</div>", unsafe_allow_html=True)

#案例2
with col_case2:
    st.image("Picture/攻击次数.png", use_container_width=True)
    st.markdown("**攻击类型占比 TOP 10**")
    st.markdown("<div style='color: #64748b; font-size: 13px;'>直观展示 PortScan、TCP-SYN 等攻击的占比。</div>", unsafe_allow_html=True)

#案例3
with col_case3:
    st.image("Picture/攻击次数.png", use_container_width=True)
    st.markdown("**流量大小对比**")
    st.markdown("<div style='color: #64748b; font-size: 13px;'>快速定位被攻击次数最多的前 10 个高风险端口。</div>", unsafe_allow_html=True)

# 案例4
with col_case4:
    st.image("Picture/攻击次数.png", use_container_width=True)
    st.markdown("**流量大小对比分析**")
    st.markdown("<div style='color: #64748b; font-size: 13px;'>双折线图对比接收与发送字节数的波动趋势。</div>", unsafe_allow_html=True)
st.markdown("<div class='sub-title'>SecureViz 网络安全日志分析与可视化平台</div>", unsafe_allow_html=True)

# 3. 渲染四张卡片
col1, col2, col3, col4 = st.columns(4, gap="large")

# 卡片 HTML 模板
def render_card(num, title, desc):
    return f"""
    <div class='card'>
        <div class='card-number'>{num}</div>
        <div class='card-title'>{title}</div>
        <div class='card-desc'>{desc}</div>
    </div>
    """

with col1:
    st.markdown(render_card("01", "数据接入", "支持 CSV / JSON 格式的网络日志文件上传，快速完成数据加载与预览。"), unsafe_allow_html=True)
    if st.button("去接入", key="btn1", use_container_width=True):
        st.switch_page("pages/1_数据分析.py")

with col2:
    st.markdown(render_card("02", "数据处理", "基于别名映射的智能列名识别，自动清洗并统一数据格式。"), unsafe_allow_html=True)
    if st.button("去处理", key="btn2", use_container_width=True):
        st.switch_page("pages/1_数据分析.py")

with col3:
    st.markdown(render_card("03", "数据分析", "生成攻击类型分布、端口排行与流量趋势等多维交互图表。"), unsafe_allow_html=True)
    if st.button("去分析", key="btn3", use_container_width=True):
        st.switch_page("pages/1_数据分析.py")

with col4:
    st.markdown(render_card("04", "数据应用", "云端部署与多终端访问，随时随地洞察网络安全态势。"), unsafe_allow_html=True)
    if st.button("去应用", key="btn4", use_container_width=True):
        st.switch_page("pages/1_数据分析.py")