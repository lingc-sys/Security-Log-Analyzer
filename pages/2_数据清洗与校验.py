import streamlit as st
import pandas as pd


st.set_page_config(page_title="数据清洗与校验", layout="wide")


st.title(" 数据清洗与校验")

st.sidebar.header("数据管理")
uploaded_file = st.sidebar.file_uploader("请上传日志文件 (CSV 或 JSON)", type=["csv", "json"])

if uploaded_file is not None:
    if uploaded_file.name.endswith('.csv'):
        df = pd.read_csv(uploaded_file)
    elif uploaded_file.name.endswith('.json'):
        df = pd.read_json(uploaded_file, lines=True)
    else:
        st.error("暂不支持该文件格式，请上传 CSV 或 JSON。")
        st.stop()

    st.subheader("数据预览")
    st.dataframe(df.head())
    st.info("🚧 数据清洗与校验功能正在建设中，敬请期待……")
else:
    st.info("👈 请从左侧侧边栏上传日志文件。")