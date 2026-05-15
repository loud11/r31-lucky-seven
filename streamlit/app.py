# app.py
import os
import re
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


def extract_json_array(text):
    """
    OpenAI 응답에서 JSON 배열만 추출
    """

    if not text:
        return []

    text = text.strip()

    try:
        return json.loads(text)
    except Exception:
        pass

    try:
        text = text.replace("```json", "").replace("```", "").strip()
        start = text.find("[")
        end = text.rfind("]") + 1

        if start != -1 and end != -1:
            return json.loads(text[start:end])

    except Exception:
        pass

    return []


def normalize_path_pattern(path):
    """
    비슷한 URL 요청을 하나의 패턴으로 묶기
    예:
    /brute/?username=admin&password=1234
    -> /brute/?username={value}&password={value}
    """

    path = str(path)

    path = re.sub(r"=([^&]+)", "={value}", path)
    path = re.sub(r"/\d+", "/{id}", path)
    path = re.sub(r"[A-Za-z0-9]{20,}", "{token}", path)

    return path


def standardize_columns(file_df):
    """
    업로드된 CSV/JSON 컬럼명을 표준 컬럼명으로 변환
    표준 컬럼:
    time, source_ip, method, path, status, size, user_agent
    """

    df = file_df.copy()
    column_map = {}

    for col in df.columns:
        lower_col = str(col).lower().strip()

        if lower_col in ["time", "timestamp", "datetime", "date", "created_at"]:
            column_map[col] = "time"

        elif lower_col in [
            "ip", "source_ip", "src_ip", "source",
            "client_ip", "remote_addr", "remote_ip"
        ]:
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

    return df[
        [
            "time",
            "source_ip",
            "method",
            "path",
            "status",
            "size",
            "user_agent"
        ]
    ]


def analyze_logs_with_openai(df, batch_size=120):
    """
    빠른 버전:
    전체 로그 row를 OpenAI에 보내지 않고,
    method + path_pattern + status + user_agent_short 기준으로 묶어서
    고유 요청 패턴만 OpenAI가 분석하게 함.
    """

    if client is None:
        st.error("OPENAI_API_KEY가 설정되어 있지 않습니다. .env 파일을 확인해 주세요.")
        return None

    df = df.copy()

    df["path_pattern"] = df["path"].apply(normalize_path_pattern)
    df["user_agent_short"] = df["user_agent"].astype(str).str[:80]

    pattern_df = (
        df.groupby(["method", "path_pattern", "status", "user_agent_short"])
        .agg(
            request_count=("path", "count"),
            sample_source_ip=("source_ip", "first"),
            sample_path=("path", "first"),
            avg_size=("size", "mean")
        )
        .reset_index()
    )

    pattern_df["pattern_id"] = pattern_df.index

    result_rows = []
    total_patterns = len(pattern_df)

    st.info(f"전체 로그 {len(df)}개 중 고유 요청 패턴 {total_patterns}개만 OpenAI가 분석합니다.")

    progress_bar = st.progress(0)
    status_message = st.empty()

    for start in range(0, total_patterns, batch_size):
        end = min(start + batch_size, total_patterns)
        batch_df = pattern_df.iloc[start:end].copy()

        patterns = []

        for _, row in batch_df.iterrows():
            patterns.append({
                "pattern_id": int(row["pattern_id"]),
                "method": str(row["method"]),
                "path_pattern": str(row["path_pattern"])[:300],
                "sample_path": str(row["sample_path"])[:300],
                "status": int(row["status"]),
                "user_agent": str(row["user_agent_short"])[:80],
                "request_count": int(row["request_count"]),
                "sample_source_ip": str(row["sample_source_ip"]),
                "avg_size": int(row["avg_size"])
            })

        prompt = f"""
너는 웹 로그 보안 분석가다.
아래 웹 요청 패턴들을 분석해서 각 pattern마다 보안 판단 결과를 만들어라.

반드시 JSON 배열만 출력해라.
설명 문장, 마크다운 코드블록은 쓰지 마라.

각 pattern마다 판단할 항목:
1. attack_type
2. severity
3. threat_score
4. ai_reason
5. recommended_action

attack_type은 아래 중 하나를 선택해라:
- Brute Force
- SQL Injection
- XSS
- Path Traversal
- Command Injection
- Scanner / Automated Tool
- Login Activity
- Error / Suspicious Request
- Suspicious Web Request
- Normal / Other

severity는 아래 중 하나를 선택해라:
- High
- Medium
- Low

threat_score는 0부터 100 사이 정수로 판단해라.
0은 정상에 가깝고, 100은 매우 위험한 요청이다.

판단할 때 반드시 고려해라:
- path_pattern
- sample_path
- method
- status
- user_agent
- request_count
- sample_source_ip
- avg_size

출력 예시:
[
  {{
    "pattern_id": 0,
    "attack_type": "Brute Force",
    "severity": "High",
    "threat_score": 88,
    "ai_reason": "로그인 관련 경로에 username과 password 파라미터가 포함되어 있고 반복 요청 수가 높아 Brute Force 가능성이 큽니다.",
    "recommended_action": "해당 IP의 로그인 요청 빈도를 제한하고 CAPTCHA, 계정 잠금, MFA를 적용하세요."
  }}
]

분석할 요청 패턴:
{json.dumps(patterns, ensure_ascii=False, indent=2)}
"""

        try:
            response = client.responses.create(
                model="gpt-4.1-mini",
                input=[
                    {
                        "role": "system",
                        "content": "너는 웹 로그 기반 보안 이벤트 분류 전문가다."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )

            parsed = extract_json_array(response.output_text)

            if not parsed:
                st.warning(f"{start + 1}~{end}번째 패턴의 OpenAI 응답을 JSON으로 읽지 못했습니다.")
            else:
                result_rows.extend(parsed)

        except Exception as e:
            st.error(f"OpenAI 로그 분석 중 오류 발생: {e}")

        progress_bar.progress(end / total_patterns)
        status_message.info(f"OpenAI가 요청 패턴을 분석 중입니다: {end}/{total_patterns}")

    progress_bar.empty()
    status_message.empty()

    result_df = pd.DataFrame(result_rows)

    if result_df.empty:
        st.error("OpenAI 분석 결과가 비어 있습니다.")
        return None

    result_df["pattern_id"] = pd.to_numeric(result_df["pattern_id"], errors="coerce")
    result_df = result_df.dropna(subset=["pattern_id"])
    result_df["pattern_id"] = result_df["pattern_id"].astype(int)

    pattern_analyzed_df = pattern_df.merge(
        result_df,
        on="pattern_id",
        how="left"
    )

    merged_df = df.merge(
        pattern_analyzed_df[
            [
                "method",
                "path_pattern",
                "status",
                "user_agent_short",
                "attack_type",
                "severity",
                "threat_score",
                "ai_reason",
                "recommended_action"
            ]
        ],
        on=["method", "path_pattern", "status", "user_agent_short"],
        how="left"
    )

    merged_df["attack_type"] = merged_df["attack_type"].fillna("Unknown")
    merged_df["severity"] = merged_df["severity"].fillna("Medium")
    merged_df["threat_score"] = pd.to_numeric(
        merged_df["threat_score"],
        errors="coerce"
    ).fillna(50).astype(int)

    merged_df["ai_reason"] = merged_df["ai_reason"].fillna("OpenAI 분석 사유가 없습니다.")
    merged_df["recommended_action"] = merged_df["recommended_action"].fillna("추가 로그 확인이 필요합니다.")

    merged_df = merged_df.drop(columns=["path_pattern", "user_agent_short"])

    return merged_df[
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
            "threat_score",
            "ai_reason",
            "recommended_action"
        ]
    ]


def parse_uploaded_file(uploaded_file):
    file_name = uploaded_file.name.lower()

    try:
        if file_name.endswith(".csv"):
            uploaded_file.seek(0)
            raw_df = pd.read_csv(uploaded_file)

            preview_text = raw_df.head(20).to_string(index=False)
            full_text = raw_df.to_string(index=False)

            base_df = standardize_columns(raw_df)
            analyzed_df = analyze_logs_with_openai(base_df, batch_size=120)

            return preview_text, full_text, analyzed_df

        elif file_name.endswith(".json"):
            uploaded_file.seek(0)
            data = json.load(uploaded_file)

            full_text = json.dumps(data, ensure_ascii=False, indent=2)
            preview_text = full_text[:3000]

            if isinstance(data, list):
                raw_df = pd.DataFrame(data)

            elif isinstance(data, dict):
                found_list = None

                for key in ["logs", "events", "detections", "data", "records", "alerts"]:
                    if key in data and isinstance(data[key], list):
                        found_list = data[key]
                        break

                if found_list is not None:
                    raw_df = pd.DataFrame(found_list)
                else:
                    raw_df = pd.DataFrame([data])

            else:
                raw_df = pd.DataFrame()

            base_df = standardize_columns(raw_df)
            analyzed_df = analyze_logs_with_openai(base_df, batch_size=120)

            return preview_text, full_text, analyzed_df

        else:
            st.error("현재는 CSV / JSON 파일만 업로드할 수 있습니다.")
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
    '<div class="sub-title">Fast Web Log Security Analytics Dashboard with OpenAI Pattern-Based Classification</div>',
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

if "last_file_signature" not in st.session_state:
    st.session_state.last_file_signature = ""

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
    st.caption("Upload Web Security Logs CSV / JSON for Fast OpenAI Pattern Analysis")

    uploaded_file = st.file_uploader(
        "분석할 웹 로그 파일을 업로드하세요.",
        type=["csv", "json"]
    )

    if uploaded_file is not None:
        file_signature = f"{uploaded_file.name}_{uploaded_file.size}"

        if st.session_state.last_file_signature != file_signature:
            st.session_state.file_analysis_result = ""
            st.session_state.dashboard_df = None

            preview_text, full_text, analyzed_df = parse_uploaded_file(uploaded_file)

            if full_text is not None and analyzed_df is not None:
                st.session_state.uploaded_file_text = shorten_text(full_text)
                st.session_state.uploaded_file_name = uploaded_file.name
                st.session_state.dashboard_df = analyzed_df
                st.session_state.last_file_signature = file_signature

                st.success(f"파일 업로드 및 OpenAI 패턴 분석 완료: {uploaded_file.name}")
                st.info("아래 그래프와 최근 탐지 내역은 OpenAI가 판단한 보안 분석 결과를 기준으로 생성됩니다.")

                with st.expander("업로드 파일 미리보기"):
                    st.text(preview_text)

        else:
            st.success(f"이미 분석된 파일입니다: {uploaded_file.name}")
            st.info("아래 그래프는 기존 OpenAI 분석 결과를 기준으로 표시됩니다.")

    if st.session_state.dashboard_df is not None:
        if st.button("OpenAI로 전체 파일 요약 분석하기"):
            if client is None:
                st.session_state.file_analysis_result = "OPENAI_API_KEY가 설정되어 있지 않습니다."
            else:
                df_for_summary = st.session_state.dashboard_df.copy()

                summary_context = df_for_summary[
                    [
                        "source_ip",
                        "method",
                        "path",
                        "status",
                        "user_agent",
                        "attack_type",
                        "severity",
                        "threat_score",
                        "ai_reason",
                        "recommended_action"
                    ]
                ].head(150).to_string(index=False)

                file_analysis_prompt = f"""
너는 웹 로그 보안 분석가다.
아래 OpenAI가 패턴 단위로 분류한 웹 로그 분석 결과를 종합해서 한국어로 설명해라.

분석 항목:
1. 전체 로그 요약
2. 주요 공격 유형
3. 위험도가 높은 IP
4. 위험도가 높은 Path
5. Status Code 관점의 이상 징후
6. User-Agent 관점의 자동화 도구 가능성
7. 위협 점수가 높은 이벤트 특징
8. 우선 대응해야 할 보안 조치
9. 초보자도 이해할 수 있는 요약

[파일 이름]
{st.session_state.uploaded_file_name}

[OpenAI 분석 결과 일부]
{summary_context}
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
        st.markdown("### AI 전체 파일 분석 결과")
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

high_risk_ip_df = (
    df[df["severity"] == "High"]
    .groupby("source_ip")
    .size()
    .reset_index(name="high_risk_count")
    .sort_values("high_risk_count", ascending=False)
    .head(10)
)

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
        st.subheader("OpenAI 공격 유형 분포")
        st.caption("Attack Types Classified by OpenAI")

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
        st.subheader("OpenAI 위험도 분포")
        st.caption("Severity Classified by OpenAI")

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
        st.subheader("OpenAI 위협 점수 분포")
        st.caption("Threat Scores Assigned by OpenAI")

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
# 고위험 IP 분석
# =========================
with st.container(border=True):
    st.subheader("고위험 요청 IP Top 10")
    st.caption("Top IPs with High Severity Requests")

    if high_risk_ip_df.empty:
        st.info("OpenAI가 High로 분류한 요청이 없습니다.")
    else:
        fig_high_ip = px.bar(
            high_risk_ip_df,
            x="source_ip",
            y="high_risk_count",
            labels={
                "source_ip": "Source IP",
                "high_risk_count": "High Risk Requests"
            }
        )

        fig_high_ip.update_layout(
            height=350,
            margin=dict(l=10, r=10, t=20, b=10),
            xaxis_tickangle=-30
        )

        st.plotly_chart(fig_high_ip, use_container_width=True)


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
    st.subheader("OpenAI 기준 의심 요청 Path Top 10")
    st.caption("Suspicious Paths Based on OpenAI Severity")

    if suspicious_path_df.empty:
        st.info("OpenAI가 의심 요청으로 분류한 Path가 없습니다.")
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
    st.caption("Recent Security Detections with OpenAI Reasoning")

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
        "attack_type": "OpenAI 공격 유형",
        "severity": "OpenAI 위험도",
        "threat_score": "OpenAI 위협 점수",
        "ai_reason": "OpenAI 판단 근거",
        "recommended_action": "권장 대응"
    })

    display_columns = [
        "시간",
        "출발지 IP",
        "Method",
        "Path",
        "Status",
        "OpenAI 공격 유형",
        "OpenAI 위험도",
        "OpenAI 위협 점수",
        "OpenAI 판단 근거",
        "권장 대응",
        "User-Agent"
    ]

    recent_df = recent_df[display_columns]

    styled_recent_df = recent_df.style.map(
        severity_color,
        subset=["OpenAI 위험도"]
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

        system_prompt = f"""
너는 웹 로그 보안 분석가이자 침해사고 분석 전문가다.
사용자의 질문에 대해 아래 OpenAI 분석 결과와 웹 로그 데이터를 바탕으로 한국어로 쉽게 설명해라.

답변 규칙:
1. 핵심 위주로 답변한다.
2. 공격 유형, 위험도, 의심 원인, 대응 방안을 포함한다.
3. 데이터에 없는 내용은 추측이라고 말한다.
4. 초보자도 이해할 수 있게 설명한다.
5. 웹 로그 기준으로 IP, Path, Status, Method, User-Agent를 함께 참고한다.
6. attack_type, severity, threat_score는 OpenAI가 요청 패턴 단위로 판단한 결과다.

[최근 OpenAI 분석 결과 일부]
{detection_context}

[OpenAI 공격 유형 통계]
{attack_summary}

[출발지 IP 통계]
{ip_summary}

[HTTP Status 통계]
{status_summary}

[요청 Path 통계]
{path_summary}

[파일 이름]
{st.session_state.uploaded_file_name}
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