import os
import json
import pandas as pd
import streamlit as st
import plotly.express as px
from dotenv import load_dotenv
from openai import OpenAI

# =========================
# 기본 설정 및 안랩 다크 테마
# =========================
load_dotenv()
st.set_page_config(page_title="Cyber Sentinel", layout="wide", initial_sidebar_state="collapsed")

st.markdown("""
    <style>
    [data-testid="stSidebar"] { display: none; }
    .main { background-color: #0E1117; color: #E0E0E0; }
    .stMetric { background: #161B22; border: 1px solid #1E3A8A; padding: 20px; border-radius: 10px; }
    h3 { color: #00D4FF; border-left: 4px solid #00D4FF; padding-left: 10px; margin: 25px 0; }
    .stButton>button { background-color: #1E3A8A; color: white; border: none; font-weight: bold; height: 50px; width: 100%; }
    .report-box { background: #111827; border: 1px solid #FF0060; padding: 20px; border-radius: 10px; }
    </style>
    """, unsafe_allow_html=True)

api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key) if api_key else None

# =========================
# 1. 파일 업로드 및 '딥 스캔' 데이터 처리
# =========================
if 'df' not in st.session_state:
    st.markdown("<div style='text-align:center; padding:100px;'><h1 style='color:#00D4FF;'>CYBER SENTINEL</h1><p>복잡한 JSON부터 CSV까지 모든 보안 로그를 정밀 분석합니다.</p></div>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        uploaded_file = st.file_uploader("LOG FILE UPLOAD", type=["csv", "json"])
        if uploaded_file:
            try:
                if uploaded_file.name.endswith('.csv'):
                    df = pd.read_csv(uploaded_file)
                else:
                    raw_data = json.load(uploaded_file)
                    # [핵심] 중첩된 JSON 구조를 완전히 평면화(Flatten)함
                    df = pd.json_normalize(raw_data, sep='_')
                st.session_state.df = df
                st.rerun()
            except Exception as e:
                st.error(f"파일 분석 실패: {e}")
else:
    df = st.session_state.df
    
    # [컬럼 검색 로직 강화] 모든 텍스트 컬럼을 합쳐서 공격을 탐지함
    # 특정 컬럼명에 의존하지 않고 데이터 전체를 훑습니다.
    def advanced_detect(row):
        # 한 줄의 모든 내용을 문자열로 합침
        full_text = " ".join(str(val).lower() for val in row.values)
        
        if any(k in full_text for k in ['nc.traditional', 'bin/sh', 'php_shell', 'rev_shell']): return "Webshell (RCE)"
        if 'union' in full_text and 'select' in full_text: return "SQL Injection"
        if '<script>' in full_text or 'alert(' in full_text: return "XSS"
        if 'etc/passwd' in full_text or '../' in full_text: return "LFI/Traversal"
        if 'brute' in full_text or 'password=' in full_text: return "Brute Force"
        return "Normal"

    # 공격 탐지 실행
    df['attack_type'] = df.apply(advanced_detect, axis=1)
    df['is_attack'] = df['attack_type'] != "Normal"
    
    # IP 컬럼 찾기 (없으면 'Source' 출력)
    ip_col = next((c for c in df.columns if any(k in c.lower() for k in ['ip', 'src', 'addr', 'source'])), None)

    # =========================
    # 2. 대시보드 출력
    # =========================
    st.markdown("<h2 style='color: #00D4FF;'>INTEGRATED SECURITY MONITORING REPORT</h2>", unsafe_allow_html=True)
    if st.button("FILE RESET"):
        del st.session_state.df
        st.rerun()
    
    st.divider()

    # 01. 현황 지표
    st.markdown("### 01. 공격 시도 및 유입 현황")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("총 로그 유입", f"{len(df):,} 건")
    attack_count = df['is_attack'].sum()
    m2.metric("공격 시도 탐지", f"{attack_count:,} 건", delta="🚨 위협 발견" if attack_count > 0 else "Stable", delta_color="inverse")
    
    top_ip = "N/A"
    if attack_count > 0 and ip_col:
        top_ip = df[df['is_attack']][ip_col].mode()[0]
    m3.metric("최다 공격 IP", top_ip)
    m4.metric("보안 위협 등급", "CRITICAL" if attack_count > 0 else "STABLE")

    # 02. 그래프 및 통계
    st.markdown("### 02. 유형별 위협 분석 현황")
    col_a, col_b = st.columns(2)
    with col_a:
        fig = px.pie(df, names='attack_type', hole=0.5, 
                     color_discrete_map={'Normal': '#36AE7C', 'Webshell (RCE)': '#FF0060', 'SQL Injection': '#F9D923', 'XSS': '#00D4FF'})
        fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color="white")
        st.plotly_chart(fig, use_container_width=True)
    with col_b:
        if attack_count > 0:
            st.write("공격 유형별 상세 카운트")
            st.bar_chart(df[df['is_attack']]['attack_type'].value_counts())
        else:
            st.info("탐지된 위협 이벤트가 없습니다.")

    # 03. AI 리포트
    st.divider()
    st.markdown("### 03. 이벤트 및 보고서 현황")
    if st.button("AI 전문가 정밀 리포트 생성"):
        with st.spinner("대용량 데이터를 분석 가능하도록 최적화 중..."):
            # 1. 공격 로그만 먼저 추출
            attacks = df[df['is_attack']]
            
            # 2. 데이터가 너무 크면 핵심만 샘플링 (전략적 요약)
            if len(attacks) > 50:
                # 공격이 많으면 최신/중요 데이터 위주로 50개만 추출
                analysis_target = attacks.head(50).to_string()
            elif len(attacks) > 0:
                analysis_target = attacks.to_string()
            else:
                # 공격이 없으면 일반 로그 일부만 추출
                analysis_target = df.head(20).to_string()

            # 3. 글자 수가 너무 길면 강제로 자르기 (API 400 에러 방지)
            if len(analysis_target) > 50000:
                analysis_target = analysis_target[:50000] + "...(중략)"

            prompt = f"""
            너는 안랩 CERT팀 수석 분석가다. 
            아래 제공된 로그에서 보안 위협 요소를 찾아내어 정밀 보고서를 작성해라.
            특히 리버스 쉘 시도(nc, php_shell)나 SQL 인젝션이 있는지 집중적으로 확인해라.

            로그 데이터 요약:
            {analysis_target}
            """
            
            try:
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}]
                )
                st.markdown(f"<div class='report-box'>{response.choices[0].message.content}</div>", unsafe_allow_html=True)
            except Exception as e:
                st.error(f"AI 분석 실패: {e}")

    # 하단 데이터
    st.markdown("#### 📋 상세 보안 이벤트 내역")
    st.dataframe(df, use_container_width=True)