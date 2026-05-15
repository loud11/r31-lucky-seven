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

api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key) if api_key else None


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


def classify_attack_type(path, method="", status=0, user_agent=""):
    path = str(path).lower()
    method = str(method).upper()
    user_agent = str(user_agent).lower()

    if "brute" in path or "username=" in path or "password=" in path:
        return "Brute Force"

    if (
        "union" in path
        or "select" in path
        or "sql" in path
        or "information_schema" in path
        or "' or" in path
        or '" or' in path
        or "1=1" in path
    ):
        return "SQL Injection"

    if (
        "xss" in path
        or "<script" in path
        or "%3cscript" in path
        or "alert(" in path
        or "onerror=" in path
    ):
        return "XSS"

    if "../" in path or "%2e%2e" in path or "etc/passwd" in path:
        return "Path Traversal"

    if "cmd=" in path or "exec" in path or "system(" in path or "shell" in path:
        return "Command Injection"

    if "nikto" in user_agent or "sqlmap" in user_agent or "nmap" in user_agent:
        return "Scanner / Automated Tool"

    if status >= 400:
        return "Error / Suspicious Request"

    if "login" in path:
        return "Login Activity"

    if method == "POST":
        return "Form Submission"

    return "Normal / Other"


def classify_severity(attack_type, status):
    high_attacks = [
        "Brute Force",
        "SQL Injection",
        "Command Injection",
        "Path Traversal",
        "Scanner / Automated Tool"
    ]

    medium_attacks = [
        "XSS",
        "Error / Suspicious Request",
        "Login Activity"
    ]

    if attack_type in high_attacks:
        return "High"

    if attack_type in medium_attacks:
        return "Medium"

    if status >= 500:
        return "High"

    if status >= 400:
        return "Medium"

    return "Low"


def calculate_threat_score(attack_type, status, path):
    score = 0
    path = str(path).lower()

    if attack_type == "Brute Force":
        score += 40
    elif attack_type == "SQL Injection":
        score += 45
    elif attack_type == "Command Injection":
        score += 50
    elif attack_type == "Path Traversal":
        score += 45
    elif attack_type == "XSS":
        score += 30
    elif attack_type == "Scanner / Automated Tool":
        score += 35
    elif attack_type == "Login Activity":
        score += 15

    if status >= 500:
        score += 25
    elif status >= 400:
        score += 15
    elif status in [301, 302, 403]:
        score += 8

    suspicious_keywords = [
        "password=",
        "username=",
        "union",
        "select",
        "<script",
        "%3cscript",
        "../",
        "cmd=",
        "etc/passwd"
    ]

    for keyword in suspicious_keywords:
        if keyword in path:
            score += 10

    return min(score, 100)


def normalize_uploaded_dataframe(file_df):
    df = file_df.copy()

    column_map = {}

    for col in df.columns:
        lower_col = str(col).lower().strip()

        if lower_col in ["time", "timestamp", "datetime", "date", "created_at"]:
            column_map[col] = "time"

        elif lower_col in ["ip", "source_ip", "src_ip", "source", "client_ip", "remote_addr", "remote_ip"]:
            column_map[col] = "source_ip"

        elif lower_col in ["method", "http_method"]:
            column_map[col] = "method"

        elif lower_col in ["path", "url", "uri", "request", "endpoint"]:
            column_map[col] = "path"

        elif lower_col in ["status", "status_code", "code"]:
            column_map[col] = "status"

        elif lower_col in ["size", "bytes", "response_size"]:
            column_map[col] = "size"

        elif lower_col in ["user_agent", "user-agent", "agent"]:
            column_map[col] = "user_agent"

    df = df.rename(columns=column_map)

    if "time" not in df.columns:
        df["time"] = pd.Timestamp.now()
    else:
        df["time"] = pd.to_datetime(
            df["time"],
            format="%d/%b/%Y:%H:%M:%S %z",
            errors="coerce"
        )

        if df["time"].isna().all():
            df["time"] = pd.to_datetime(df["time"], errors="coerce")

        df["time"] = df["time"].fillna(pd.Timestamp.now())

    if "source_ip" not in df.columns:
        df["source_ip"] = "Unknown"

    if "method" not in df.columns:
        df["method"] = "Unknown"

    if "path" not in df.columns:
        df["path"] = "Unknown"

    if "status" not in df.columns:
        df["status"] = 0

    if "size" not in df.columns:
        df["size"] = 0

    if "user_agent" not in df.columns:
        df["user_agent"] = "Unknown"

    df["source_ip"] = df["source_ip"].fillna("Unknown").astype(str)
    df["method"] = df["method"].fillna("Unknown").astype(str)
    df["path"] = df["path"].fillna("Unknown").astype(str)
    df["user_agent"] = df["user_agent"].fillna("Unknown").astype(str)

    df["status"] = pd.to_numeric(df["status"], errors="coerce").fillna(0).astype(int)
    df["size"] = pd.to_numeric(df["size"], errors="coerce").fillna(0).astype(int)

    df["attack_type"] = df.apply(
        lambda row: classify_attack_type(
            row["path"],
            row["method"],
            row["status"],
            row["user_agent"]
        ),
        axis=1
    )

    df["severity"] = df.apply(
        lambda row: classify_severity(row["attack_type"], row["status"]),
        axis=1
    )

    df["threat_score"] = df.apply(
        lambda row: calculate_threat_score(
            row["attack_type"],
            row["status"],
            row["path"]
        ),
        axis=1
    )

    return df[
        [
            "time",
            "source_ip",
            "method",
            "path",
            "status",
            "size",
            "user_agent",
            "attack_type",
            "severity",
            "threat_score"
        ]
    ]


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


def severity_color(value):
    if value == "High":
        return "color: #e63946; font-weight: bold;"
    if value == "Medium":
        return "color: #f4a261; font-weight: bold;"
    if value == "Low":
        return "color: #2a9d8f; font-weight: bold;"
    return ""


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
        margin-top: 10px;
        margin-bottom: 12px;
    }

    .summary-text {
        text-align: center;
        font-size: 18px;
        font-weight: 700;
        color: #222;
    }

    .metric-small {
        text-align: center;
        font-size: 14px;
        color: #666;
        margin-top: 8px;
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
    '<div class="main-title">🛡️ AI 기반 웹 로그 보안 분석 대시보드</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="sub-title">Web Log Security Analytics Dashboard with OpenAI Chatbot</div>',
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
            "content": "안녕하세요. 웹 로그 파일을 업로드한 뒤 탐지 결과나 그래프에 대해 질문해 주세요."
        }
    ]


# =========================
# 파일 업로드 및 OpenAI 분석
# =========================
with st.container(border=True):
    st.subheader("파일 업로드 분석")
    st.caption("Upload Web Security Logs CSV / JSON for Dashboard and AI Analysis")

    uploaded_file = st.file_uploader(
        "분석할 웹 로그 파일을 업로드하세요.",
        type=["csv", "json"]
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
                if client is None:
                    st.session_state.file_analysis_result = "OPENAI_API_KEY가 설정되어 있지 않습니다."
                else:
                    file_analysis_prompt = f"""
너는 웹 로그 보안 분석가다.
아래 업로드된 웹 로그 내용을 분석해서 한국어로 설명해라.

분석 항목:
1. 전체 로그 요약
2. 의심되는 공격 유형
3. Brute Force, SQL Injection, XSS, Path Traversal 가능성
4. 가장 많이 요청한 IP
5. 많이 요청된 URL Path
6. HTTP Status Code 관점의 이상 징후
7. User-Agent 관점의 자동화 도구 가능성
8. 보안 대응 방안
9. 초보자도 이해할 수 있는 요약

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
                                    "content": "너는 웹 로그 분석과 침해사고 분석에 능숙한 보안 관제 분석가다."
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
    st.warning("대시보드를 보려면 먼저 CSV 또는 JSON 웹 로그 파일을 업로드하세요.")
    st.stop()


# =========================
# 업로드 파일 기반 데이터 준비
# =========================
df = st.session_state.dashboard_df.copy()

total_requests = len(df)
unique_ips = df["source_ip"].nunique()
high_count = len(df[df["severity"] == "High"])
medium_count = len(df[df["severity"] == "Medium"])
low_count = len(df[df["severity"] == "Low"])
avg_threat_score = round(df["threat_score"].mean(), 1)
max_threat_score = int(df["threat_score"].max())

attack_count_df = df["attack_type"].value_counts().reset_index()
attack_count_df.columns = ["attack_type", "count"]

source_ip_df = df["source_ip"].value_counts().head(10).reset_index()
source_ip_df.columns = ["source_ip", "count"]

status_df = df["status"].value_counts().reset_index()
status_df.columns = ["status", "count"]
status_df["status"] = status_df["status"].astype(str)

method_df = df["method"].value_counts().reset_index()
method_df.columns = ["method", "count"]

severity_df = df["severity"].value_counts().reset_index()
severity_df.columns = ["severity", "count"]

top_path_df = df["path"].value_counts().head(10).reset_index()
top_path_df.columns = ["path", "count"]

user_agent_df = df["user_agent"].value_counts().head(10).reset_index()
user_agent_df.columns = ["user_agent", "count"]

suspicious_df = df[df["severity"].isin(["High", "Medium"])].copy()
suspicious_path_df = suspicious_df["path"].value_counts().head(10).reset_index()
suspicious_path_df.columns = ["path", "count"]

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
                <div class="summary-number">{total_requests}</div>
                <div class="summary-text">
                    전체 요청 수<br>
                    High: {high_count} / Medium: {medium_count} / Low: {low_count}
                </div>
                <div class="metric-small">
                    Unique IP: {unique_ips} | Avg Threat Score: {avg_threat_score}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

with col2:
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
            height=280,
            margin=dict(l=10, r=10, t=20, b=10),
            xaxis_tickangle=-30
        )

        st.plotly_chart(fig_attack, use_container_width=True)

with col3:
    with st.container(border=True):
        st.subheader("출발지 IP Top 10")
        st.caption("Top Source IPs by Request Count")

        fig_ip = px.bar(
            source_ip_df,
            x="source_ip",
            y="count",
            labels={
                "source_ip": "Source IP",
                "count": "Requests"
            }
        )

        fig_ip.update_layout(
            height=280,
            margin=dict(l=10, r=10, t=20, b=10),
            xaxis_tickangle=-30
        )

        st.plotly_chart(fig_ip, use_container_width=True)


# =========================
# 중간 그래프 2개
# =========================
col4, col5 = st.columns(2)

with col4:
    with st.container(border=True):
        st.subheader("HTTP Status Code 분포")
        st.caption("Response Status Distribution")

        fig_status = px.bar(
            status_df,
            x="status",
            y="count",
            labels={
                "status": "HTTP Status",
                "count": "Count"
            }
        )

        fig_status.update_layout(
            height=330,
            margin=dict(l=10, r=10, t=20, b=10)
        )

        st.plotly_chart(fig_status, use_container_width=True)

with col5:
    with st.container(border=True):
        st.subheader("HTTP Method 분포")
        st.caption("Request Method Distribution")

        fig_method = px.pie(
            method_df,
            names="method",
            values="count",
            hole=0.45
        )

        fig_method.update_layout(
            height=330,
            margin=dict(l=10, r=10, t=20, b=10)
        )

        st.plotly_chart(fig_method, use_container_width=True)


# =========================
# 위험도 / 위협 점수 그래프
# =========================
col6, col7 = st.columns(2)

with col6:
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
            height=330,
            margin=dict(l=10, r=10, t=20, b=10)
        )

        st.plotly_chart(fig_severity, use_container_width=True)

with col7:
    with st.container(border=True):
        st.subheader("위협 점수 분포")
        st.caption("Threat Score Distribution")

        fig_score = px.histogram(
            df,
            x="threat_score",
            nbins=10,
            labels={
                "threat_score": "Threat Score"
            }
        )

        fig_score.update_layout(
            height=330,
            margin=dict(l=10, r=10, t=20, b=10)
        )

        st.plotly_chart(fig_score, use_container_width=True)


# =========================
# URL Path 분석
# =========================
with st.container(border=True):
    st.subheader("요청 Path Top 10")
    st.caption("Most Requested URL Paths")

    fig_path = px.bar(
        top_path_df,
        x="count",
        y="path",
        orientation="h",
        labels={
            "count": "Requests",
            "path": "Path"
        }
    )

    fig_path.update_layout(
        height=420,
        margin=dict(l=10, r=10, t=20, b=10)
    )

    st.plotly_chart(fig_path, use_container_width=True)


with st.container(border=True):
    st.subheader("의심 요청 Path Top 10")
    st.caption("Top Suspicious URL Paths")

    if suspicious_path_df.empty:
        st.info("의심 요청으로 분류된 Path가 없습니다.")
    else:
        fig_suspicious_path = px.bar(
            suspicious_path_df,
            x="count",
            y="path",
            orientation="h",
            labels={
                "count": "Suspicious Requests",
                "path": "Suspicious Path"
            }
        )

        fig_suspicious_path.update_layout(
            height=420,
            margin=dict(l=10, r=10, t=20, b=10)
        )

        st.plotly_chart(fig_suspicious_path, use_container_width=True)


# =========================
# User-Agent 분석
# =========================
with st.container(border=True):
    st.subheader("User-Agent Top 10")
    st.caption("Most Common User Agents")

    fig_user_agent = px.bar(
        user_agent_df,
        x="count",
        y="user_agent",
        orientation="h",
        labels={
            "count": "Requests",
            "user_agent": "User-Agent"
        }
    )

    fig_user_agent.update_layout(
        height=380,
        margin=dict(l=10, r=10, t=20, b=10)
    )

    st.plotly_chart(fig_user_agent, use_container_width=True)


# =========================
# 최근 탐지 내역
# =========================
with st.container(border=True):
    st.subheader("최근 탐지 내역")
    st.caption("Recent Security Detections")

    recent_df = df.sort_values("time", ascending=False).copy()
    recent_df["time"] = recent_df["time"].dt.strftime("%Y-%m-%d %H:%M:%S")

    recent_df = recent_df.rename(columns={
        "time": "시간",
        "source_ip": "출발지 IP",
        "method": "Method",
        "path": "Path",
        "status": "Status",
        "size": "Size",
        "user_agent": "User-Agent",
        "attack_type": "공격 유형",
        "severity": "위험도",
        "threat_score": "위협 점수"
    })

    display_columns = [
        "시간",
        "출발지 IP",
        "Method",
        "Path",
        "Status",
        "공격 유형",
        "위험도",
        "위협 점수",
        "User-Agent"
    ]

    recent_df = recent_df[display_columns]

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

        detection_context = df.head(120).to_string(index=False)
        attack_summary = attack_count_df.to_string(index=False)
        ip_summary = source_ip_df.to_string(index=False)
        status_summary = status_df.to_string(index=False)
        path_summary = top_path_df.to_string(index=False)

        uploaded_file_context = st.session_state.get("uploaded_file_text", "")
        uploaded_file_name = st.session_state.get("uploaded_file_name", "")

        system_prompt = f"""
너는 웹 로그 보안 분석가이자 침해사고 분석 전문가다.
사용자의 질문에 대해 아래 웹 로그 분석 데이터와 업로드 파일 내용을 바탕으로 한국어로 쉽게 설명해라.

답변 규칙:
1. 핵심 위주로 답변한다.
2. 공격 유형, 위험도, 의심 원인, 대응 방안을 포함한다.
3. 데이터에 없는 내용은 추측이라고 말한다.
4. 초보자도 이해할 수 있게 설명한다.
5. 웹 로그 기준으로 IP, Path, Status, Method, User-Agent를 함께 참고한다.

[최근 탐지 데이터 일부]
{detection_context}

[공격 유형 통계]
{attack_summary}

[출발지 IP 통계]
{ip_summary}

[HTTP Status 통계]
{status_summary}

[요청 Path 통계]
{path_summary}

[업로드 파일 이름]
{uploaded_file_name}

[업로드 파일 내용 일부]
{uploaded_file_context}
"""

        if client is None:
            ai_answer = "OPENAI_API_KEY가 설정되어 있지 않습니다. .env 파일에 OPENAI_API_KEY를 추가해 주세요."
        else:
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