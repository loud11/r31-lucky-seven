# app.py
import os
import json
import pandas as pd
import streamlit as st
import plotly.express as px
from dotenv import load_dotenv
from openai import OpenAI

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
# 유틸 함수
# =========================
def shorten_text(text, max_chars=12000):
    if text is None:
        return ""

    text = str(text)

    if len(text) > max_chars:
        return text[:max_chars] + "\n\n...파일 내용이 길어 일부만 분석에 사용되었습니다."

    return text


def normalize_uploaded_dataframe(file_df):
    """
    업로드된 CSV/JSON 컬럼명을 대시보드 표준 컬럼명으로 변환
    표준 컬럼:
    time, attack_type, source_ip, severity
    """

    df = file_df.copy()
    column_map = {}

    for col in df.columns:
        lower_col = str(col).lower().strip()

        if lower_col in ["time", "timestamp", "datetime", "date", "created_at"]:
            column_map[col] = "time"

        elif lower_col in [
            "attack_type", "attack", "type", "event_type",
            "threat", "alert", "category", "signature", "event", "message"
        ]:
            column_map[col] = "attack_type"

        elif lower_col in [
            "source_ip", "src_ip", "source", "src",
            "client_ip", "ip", "remote_addr", "remote_ip"
        ]:
            column_map[col] = "source_ip"

        elif lower_col in ["severity", "risk", "level", "priority"]:
            column_map[col] = "severity"

    df = df.rename(columns=column_map)

    if "time" not in df.columns:
        df["time"] = pd.Timestamp.now()
    else:
        df["time"] = pd.to_datetime(df["time"], errors="coerce")
        df["time"] = df["time"].fillna(pd.Timestamp.now())

    if "attack_type" not in df.columns:
        df["attack_type"] = "Uploaded Event"

    if "source_ip" not in df.columns:
        df["source_ip"] = "Unknown"

    if "severity" not in df.columns:
        df["severity"] = "Medium"

    df["attack_type"] = df["attack_type"].fillna("Unknown").astype(str)
    df["source_ip"] = df["source_ip"].fillna("Unknown").astype(str)
    df["severity"] = df["severity"].fillna("Medium").astype(str)

    df["severity"] = df["severity"].str.capitalize()

    return df[["time", "attack_type", "source_ip", "severity"]]


def parse_uploaded_file(uploaded_file):
    file_name = uploaded_file.name.lower()

    try:
        if file_name.endswith(".csv"):
            uploaded_file.seek(0)
            file_df = pd.read_csv(uploaded_file)

            preview_text = file_df.head(20).to_string(index=False)
            full_text = file_df.to_string(index=False)

            dashboard_df = normalize_uploaded_dataframe(file_df)

            return preview_text, full_text, dashboard_df

        elif file_name.endswith(".json"):
            uploaded_file.seek(0)
            data = json.load(uploaded_file)

            full_text = json.dumps(data, ensure_ascii=False, indent=2)
            preview_text = full_text[:3000]

            if isinstance(data, list):
                file_df = pd.DataFrame(data)

            elif isinstance(data, dict):
                found_list = None

                for key in ["logs", "events", "detections", "data", "records", "alerts"]:
                    if key in data and isinstance(data[key], list):
                        found_list = data[key]
                        break

                if found_list is not None:
                    file_df = pd.DataFrame(found_list)
                else:
                    file_df = pd.DataFrame([data])

            else:
                file_df = pd.DataFrame()

            dashboard_df = normalize_uploaded_dataframe(file_df)

            return preview_text, full_text, dashboard_df

        else:
            st.error("현재는 JSON / CSV 파일만 업로드할 수 있습니다.")
            return None, None, None

    except Exception as e:
        st.error(f"파일을 읽는 중 오류가 발생했습니다: {e}")
        return None, None, None


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
# 세션 상태 초기화
# =========================
if "uploaded_file_text" not in st.session_state:
    st.session_state.uploaded_file_text = ""

if "uploaded_file_name" not in st.session_state:
    st.session_state.uploaded_file_name = ""

if "dashboard_df" not in st.session_state:
    st.session_state.dashboard_df = None

if "file_analysis_result" not in st.session_state:
    st.session_state.file_analysis_result = ""

if "messages" not in st.session_state:
    st.session_state.messages = [
        {
            "role": "assistant",
            "content": "안녕하세요. 파일을 업로드한 뒤 탐지 데이터나 그래프에 대해 질문해 주세요."
        }
    ]


# =========================
# 파일 업로드 및 OpenAI 분석
# =========================
with st.container(border=True):
    st.subheader("파일 업로드 분석")
    st.caption("Upload Security Logs JSON / CSV for Dashboard and AI Analysis")

    uploaded_file = st.file_uploader(
        "분석할 파일을 업로드하세요.",
        type=["json", "csv"]
    )

    if uploaded_file is not None:
        preview_text, full_text, uploaded_df = parse_uploaded_file(uploaded_file)

        if full_text is not None and uploaded_df is not None:
            st.session_state.uploaded_file_text = shorten_text(full_text)
            st.session_state.uploaded_file_name = uploaded_file.name
            st.session_state.dashboard_df = uploaded_df

            st.success(f"파일 업로드 완료: {uploaded_file.name}")
            st.info("아래 그래프와 최근 탐지 내역이 업로드 파일 기준으로 생성됩니다.")

            with st.expander("업로드 파일 미리보기"):
                st.text(preview_text)

            if st.button("OpenAI로 파일 분석하기"):
                file_analysis_prompt = f"""
너는 보안 로그 분석가다.
아래 업로드된 파일 내용을 분석해서 한국어로 설명해라.

분석 항목:
1. 파일에서 보이는 주요 이상 징후
2. 의심되는 공격 유형
3. 위험도가 높은 이벤트
4. 반복적으로 등장하는 IP, URL, 계정, 에러 패턴
5. 보안 대응 방안
6. 초보자도 이해할 수 있는 요약

[파일 이름]
{st.session_state.uploaded_file_name}

[파일 내용]
{st.session_state.uploaded_file_text}
"""

                try:
                    response = client.responses.create(
                        model="gpt-4.1-mini",
                        input=[
                            {
                                "role": "system",
                                "content": "너는 보안 관제 분석가이자 침해사고 분석 전문가다."
                            },
                            {
                                "role": "user",
                                "content": file_analysis_prompt
                            }
                        ]
                    )

                    st.session_state.file_analysis_result = response.output_text

                except Exception as e:
                    st.session_state.file_analysis_result = f"OpenAI API 호출 중 오류가 발생했습니다: {e}"

    if st.session_state.file_analysis_result:
        st.markdown("### AI 파일 분석 결과")
        st.write(st.session_state.file_analysis_result)


# =========================
# 파일 업로드 전 화면
# =========================
if st.session_state.dashboard_df is None:
    st.warning("그래프와 최근 탐지 내역을 보려면 먼저 JSON 또는 CSV 파일을 업로드하세요.")
    st.stop()


# =========================
# 업로드 파일 기반 대시보드 데이터 준비
# =========================
df = st.session_state.dashboard_df.copy()

df["time"] = pd.to_datetime(df["time"], errors="coerce")
df["time"] = df["time"].fillna(pd.Timestamp.now())

total_detected = len(df)
high_count = len(df[df["severity"] == "High"])
medium_count = len(df[df["severity"] == "Medium"])
low_count = len(df[df["severity"] == "Low"])

severity_df = df["severity"].value_counts().reset_index()
severity_df.columns = ["severity", "count"]

source_ip_df = df["source_ip"].value_counts().head(10).reset_index()
source_ip_df.columns = ["source_ip", "count"]

attack_count_df = df["attack_type"].value_counts().reset_index()
attack_count_df.columns = ["attack_type", "count"]

st.caption(f"현재 데이터 기준: 업로드 파일 - {st.session_state.uploaded_file_name}")


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
                <div class="summary-text">
                    전체 탐지 이벤트<br>
                    High: {high_count} / Medium: {medium_count} / Low: {low_count}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

with col2:
    with st.container(border=True):
        st.subheader("위험도 분포")
        st.caption("Severity Distribution")

        fig_severity = px.bar(
            severity_df,
            x="severity",
            y="count",
            labels={
                "severity": "Severity",
                "count": "Count"
            }
        )

        fig_severity.update_layout(
            height=280,
            margin=dict(l=10, r=10, t=20, b=10)
        )

        st.plotly_chart(fig_severity, use_container_width=True)

with col3:
    with st.container(border=True):
        st.subheader("출발지 IP Top 10")
        st.caption("Top Source IPs")

        fig_source_ip = px.bar(
            source_ip_df,
            x="source_ip",
            y="count",
            labels={
                "source_ip": "Source IP",
                "count": "Count"
            }
        )

        fig_source_ip.update_layout(
            height=280,
            margin=dict(l=10, r=10, t=20, b=10),
            xaxis_tickangle=-35
        )

        st.plotly_chart(fig_source_ip, use_container_width=True)


# =========================
# 공격 유형 분포
# =========================
with st.container(border=True):
    st.subheader("공격 유형 분포")
    st.caption("Attack Type Distribution")

    fig_attack = px.bar(
        attack_count_df,
        x="attack_type",
        y="count",
        labels={
            "attack_type": "Attack Type",
            "count": "Count"
        }
    )

    fig_attack.update_layout(
        height=330,
        margin=dict(l=10, r=10, t=20, b=10),
        xaxis_tickangle=-35
    )

    st.plotly_chart(fig_attack, use_container_width=True)


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

    user_question = st.chat_input("업로드 파일이나 이상 징후에 대해 질문하세요.")

    if user_question:
        st.session_state.messages.append({
            "role": "user",
            "content": user_question
        })

        detection_context = df.to_string(index=False)
        attack_summary = attack_count_df.to_string(index=False)

        uploaded_file_context = st.session_state.get("uploaded_file_text", "")
        uploaded_file_name = st.session_state.get("uploaded_file_name", "")

        system_prompt = f"""
너는 보안 관제 분석가이자 웹 취약점 분석 전문가다.
사용자의 질문에 대해 아래 탐지 데이터와 업로드 파일 내용을 바탕으로 한국어로 쉽게 설명해라.

답변 규칙:
1. 너무 길지 않게 핵심 위주로 설명한다.
2. 공격 유형, 위험도, 의심 원인, 대응 방안을 포함한다.
3. 데이터에 없는 내용은 추측이라고 말한다.
4. 초보자도 이해할 수 있게 설명한다.
5. 필요하면 WAF, 입력값 검증, 계정 잠금, IP 차단, 로그 분석 같은 대응책을 제안한다.
6. 업로드 파일이 있으면 반드시 함께 참고한다.

[현재 그래프 기준 탐지 데이터]
{detection_context}

[공격 유형 통계]
{attack_summary}

[업로드 파일 이름]
{uploaded_file_name}

[업로드 파일 내용]
{uploaded_file_context}
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