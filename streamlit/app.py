import os
import pandas as pd
import streamlit as st
import plotly.express as px
from dotenv import load_dotenv
from openai import OpenAI
import requests

# =========================
# 기본 설정
# =========================
load_dotenv()

st.set_page_config(
    page_title="AI Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


# =========================
# 나중에 실제 데이터로 교체할 부분
# =========================
def load_detection_data():
    return pd.DataFrame({
        "time": [
            "2024-05-20 10:21:15",
            "2024-05-20 10:20:31",
            "2024-05-20 10:19:02",
            "2024-05-20 10:18:45",
            "2024-05-20 10:17:30",
            "2024-05-20 10:16:10",
        ],
        "attack_type": [
            "SQL Injection",
            "XSS",
            "Brute Force",
            "SQL Injection",
            "Port Scan",
            "XSS",
        ],
        "source_ip": [
            "192.168.1.23",
            "192.168.1.45",
            "192.168.1.99",
            "192.168.1.23",
            "192.168.1.77",
            "192.168.1.45",
        ],
        "severity": [
            "High",
            "Medium",
            "High",
            "High",
            "Low",
            "Medium",
        ]
    })

# def load_detection_data():
#     response = requests.get("http://127.0.0.1:8000/detections")
#     return pd.DataFrame(response.json())


def load_traffic_data():
    return pd.DataFrame({
        "time": ["10:00", "10:05", "10:10", "10:15", "10:20", "10:25", "10:30"],
        "normal_traffic": [120, 150, 130, 180, 160, 210, 240],
        "suspicious_traffic": [20, 35, 30, 60, 45, 70, 95],
    })
# def load_traffic_data():
#     response = requests.get("http://127.0.0.1:8000/traffic")
#     return pd.DataFrame(response.json())

# =========================
# 데이터 준비
# =========================
df = load_detection_data()
traffic_df = load_traffic_data()

df["time"] = pd.to_datetime(df["time"])

total_detected = len(df)

attack_count_df = df["attack_type"].value_counts().reset_index()
attack_count_df.columns = ["attack_type", "count"]

time_trend_df = (
    df.groupby(pd.Grouper(key="time", freq="5min"))
    .size()
    .reset_index(name="detections")
)


# =========================
# CSS
# =========================
st.markdown(
    """
    <style>
    .stApp {
        background-color: #f7f9fb;
    }

    .block-container {
        padding-top: 3rem;
        padding-bottom: 3rem;
    }

    .main-title {
        font-size: 34px;
        font-weight: 800;
        margin-bottom: 4px;
        color: #222;
    }

    .sub-title {
        color: #666;
        margin-bottom: 24px;
        font-size: 15px;
    }

    div[data-testid="stVerticalBlockBorderWrapper"] {
        background-color: white;
        border-radius: 16px;
        box-shadow: 0 3px 10px rgba(0,0,0,0.05);
    }

    .summary-card-wrapper {
        height: 295px;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        padding-top: 10px;
    }

    .summary-number {
        font-size: 58px;
        font-weight: 900;
        color: #e63946;
        text-align: center;
        margin-top: 20px;
        margin-bottom: 12px;
    }

    .summary-text {
        text-align: center;
        font-size: 18px;
        font-weight: 700;
        color: #222;
    }

    .chat-user {
        background-color: #dff1ff;
        color: #111;
        padding: 14px 16px;
        border-radius: 14px;
        margin: 10px 0;
        width: fit-content;
        max-width: 85%;
    }

    .chat-ai {
        background-color: #f1f1f1;
        color: #111;
        padding: 14px 16px;
        border-radius: 14px;
        margin: 10px 0 10px auto;
        width: fit-content;
        max-width: 85%;
    }

    h2, h3 {
        color: #222;
    }
    </style>
    """,
    unsafe_allow_html=True
)


# =========================
# 제목
# =========================
st.markdown(
    '<div class="main-title">🛡️ AI 기반 보안 탐지 대시보드</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="sub-title">Threat Detection Dashboard with OpenAI Chatbot</div>',
    unsafe_allow_html=True
)


# =========================
# 상단 카드 3개
# =========================
col1, col2, col3 = st.columns(3)

with col1:
    with st.container(border=True):
        st.subheader("위험 요약")
        st.caption("Threat Summary")

        st.markdown(
            f"""
            <div class="summary-card-wrapper">
                <div class="summary-number">{total_detected}</div>
                <div class="summary-text">위험 탐지<br>(Detected)</div>
            </div>
            """,
            unsafe_allow_html=True
        )

with col2:
    with st.container(border=True):
        st.subheader("트래픽 통계")
        st.caption("Traffic Statistics")

        fig_traffic = px.line(
            traffic_df,
            x="time",
            y=["normal_traffic", "suspicious_traffic"],
            markers=True,
            labels={
                "time": "Time",
                "value": "Traffic",
                "variable": "Type"
            }
        )

        fig_traffic.update_layout(
            height=280,
            margin=dict(l=10, r=10, t=20, b=10),
            legend=dict(
                orientation="h",
                y=-0.25,
                x=0.5,
                xanchor="center"
            )
        )

        st.plotly_chart(fig_traffic, use_container_width=True)

with col3:
    with st.container(border=True):
        st.subheader("주요 공격 유형")
        st.caption("Top Attack Types")

        fig_attack = px.pie(
            attack_count_df,
            names="attack_type",
            values="count",
            hole=0.55
        )

        fig_attack.update_layout(
            height=280,
            margin=dict(l=10, r=10, t=20, b=10),
            legend=dict(
                orientation="h",
                y=-0.25,
                x=0.5,
                xanchor="center"
            )
        )

        st.plotly_chart(fig_attack, use_container_width=True)


# =========================
# 시간별 탐지 추이
# =========================
with st.container(border=True):
    st.subheader("시간별 탐지 추이")
    st.caption("Detections Over Time")

    fig_trend = px.line(
        time_trend_df,
        x="time",
        y="detections",
        markers=True,
        labels={
            "time": "Time",
            "detections": "Detections"
        }
    )

    fig_trend.update_traces(fill="tozeroy")

    fig_trend.update_layout(
        height=330,
        margin=dict(l=10, r=10, t=20, b=10)
    )

    st.plotly_chart(fig_trend, use_container_width=True)


# =========================
# 최근 탐지 내역
# =========================
with st.container(border=True):
    st.subheader("최근 탐지 내역")
    st.caption("Recent Detections")

    recent_df = df.sort_values("time", ascending=False).copy()
    recent_df["time"] = recent_df["time"].dt.strftime("%Y-%m-%d %H:%M:%S")

    recent_df = recent_df.rename(columns={
        "time": "시간",
        "attack_type": "공격 유형",
        "source_ip": "출발지 IP",
        "severity": "위험도"
    })

    def severity_color(value):
        if value == "High":
            return "color: #e63946; font-weight: bold;"
        if value == "Medium":
            return "color: #f4a261; font-weight: bold;"
        if value == "Low":
            return "color: #2a9d8f; font-weight: bold;"
        return ""

    styled_recent_df = recent_df.style.map(
        severity_color,
        subset=["위험도"]
    )

    st.dataframe(
        styled_recent_df,
        use_container_width=True,
        hide_index=True
    )


# =========================
# OpenAI 챗봇
# =========================
with st.container(border=True):
    st.subheader("AI 기반 분석/설명")
    st.caption("OpenAI Security Assistant")

    if "messages" not in st.session_state:
        st.session_state.messages = [
            {
                "role": "assistant",
                "content": "안녕하세요. 탐지된 이상 징후에 대해 질문해 주세요. 예: 이 시간대에 SQL Injection이 왜 위험해?"
            }
        ]

    for message in st.session_state.messages:
        if message["role"] == "user":
            st.markdown(
                f"""
                <div class="chat-user">
                    👤 {message["content"]}
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f"""
                <div class="chat-ai">
                    🤖 {message["content"]}
                </div>
                """,
                unsafe_allow_html=True
            )

    user_question = st.chat_input("이상 징후에 대해 질문하세요.")

    if user_question:
        st.session_state.messages.append({
            "role": "user",
            "content": user_question
        })

        detection_context = df.to_string(index=False)
        attack_summary = attack_count_df.to_string(index=False)
        trend_summary = time_trend_df.to_string(index=False)

        system_prompt = f"""
너는 보안 관제 분석가이자 웹 취약점 분석 전문가다.
사용자의 질문에 대해 아래 탐지 데이터를 바탕으로 한국어로 쉽게 설명해라.

답변 규칙:
1. 너무 길지 않게 핵심 위주로 설명한다.
2. 공격 유형, 위험도, 의심 원인, 대응 방안을 포함한다.
3. 데이터에 없는 내용은 추측이라고 말한다.
4. 초보자도 이해할 수 있게 설명한다.
5. 필요하면 WAF, 입력값 검증, 계정 잠금, IP 차단, 로그 분석 같은 대응책을 제안한다.

[최근 탐지 데이터]
{detection_context}

[공격 유형 통계]
{attack_summary}

[시간별 탐지 추이]
{trend_summary}
"""

        try:
            response = client.responses.create(
                model="gpt-4.1-mini",
                input=[
                    {
                        "role": "system",
                        "content": system_prompt
                    },
                    {
                        "role": "user",
                        "content": user_question
                    }
                ]
            )

            ai_answer = response.output_text

        except Exception as e:
            ai_answer = f"OpenAI API 호출 중 오류가 발생했습니다: {e}"

        st.session_state.messages.append({
            "role": "assistant",
            "content": ai_answer
        })

        st.rerun()
