import streamlit as st
import pandas as pd
import plotly.express as px
from log_analyzer.parser import LogParser
from log_analyzer.analyzer import LogAnalyzer
from log_analyzer.security_detector import SecurityDetector
import os

# Page Configuration
st.set_page_config(page_title="Security Log Analyzer Dashboard", layout="wide")

st.title("🛡️ Security Log Analyzer Dashboard")
st.markdown("### Interactive Cybersecurity Monitoring & Threat Detection")

# Sidebar for file upload or sample selection
st.sidebar.header("Data Source")
log_file_path = st.sidebar.text_input("Log File Path", value="log_analyzer/sample_logs.log")

if os.path.exists(log_file_path):
    # 1. Load and Parse Logs
    logs = LogParser.parse_file(log_file_path)
    
    if logs:
        # 2. Analyze Logs
        analyzer = LogAnalyzer(logs)
        results = analyzer.get_summary()
        detector = SecurityDetector(logs)
        alerts = detector.get_all_security_alerts()

        # Dashboard layout
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Logs", results['total_logs'])
        col2.metric("INFO", results['level_counts'].get('INFO', 0))
        col3.metric("WARNING", results['level_counts'].get('WARNING', 0))
        col4.metric("ERROR", results['level_counts'].get('ERROR', 0))

        # Charts Section
        st.divider()
        c1, c2 = st.columns(2)

        with c1:
            st.subheader("Log Level Distribution")
            df_levels = pd.DataFrame(list(results['level_counts'].items()), columns=['Level', 'Count'])
            fig_pie = px.pie(df_levels, values='Count', names='Level', color='Level',
                            color_discrete_map={'INFO':'blue', 'WARNING':'orange', 'ERROR':'red'})
            st.plotly_chart(fig_pie, use_container_width=True)

        with c2:
            st.subheader("Hourly Activity")
            df_hourly = pd.DataFrame(list(results['hourly_activity'].items()), columns=['Hour', 'Count']).sort_values('Hour')
            fig_bar = px.bar(df_hourly, x='Hour', y='Count', title="Log Activity per Hour")
            st.plotly_chart(fig_bar, use_container_width=True)

        # Security Alerts Section
        st.divider()
        st.subheader("🚨 Security Alerts")
        
        # Display alerts in an expander
        with st.expander("Security Alert Details", expanded=True):
            if alerts['brute_force_alerts']:
                for alert in alerts['brute_force_alerts']:
                    st.error(f"**{alert['type']} detected from {alert['ip']}** ({alert['attempts']} attempts)")
            
            if alerts['scanning_alerts']:
                for alert in alerts['scanning_alerts']:
                    st.warning(f"**{alert['type']} detected from {alert['ip']}** ({alert['unique_errors']} unique endpoints)")

            if alerts['traffic_alerts']:
                for alert in alerts['traffic_alerts']:
                    st.error(f"**{alert['type']} from {alert['ip']}** ({alert['total_requests']} requests)")

            if alerts['keyword_alerts']:
                st.warning(f"**{len(alerts['keyword_alerts'])} suspicious keywords detected** in log messages.")
                df_alerts = pd.DataFrame([ { 'Type': a['type'], 'Keyword': a['keyword'], 'Message': a['log']['message']} for a in alerts['keyword_alerts']])
                st.table(df_alerts)

        # Log Data Table
        st.divider()
        st.subheader("📜 Recent Log Entries")
        df_logs = pd.DataFrame(logs)
        st.dataframe(df_logs[['timestamp', 'level', 'message', 'ip']], use_container_width=True)

    else:
        st.error("Could not parse logs from the provided file.")
else:
    st.info("Please provide a valid log file path in the sidebar to start analysis.")
