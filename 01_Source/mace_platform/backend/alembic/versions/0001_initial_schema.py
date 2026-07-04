"""Initial schema — all MACE platform tables

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-05-11
"""
from alembic import op
import sqlalchemy as sa

revision = '0001_initial_schema'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # tenants
    op.create_table('tenants',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(100), unique=True, nullable=False),
        sa.Column('domain', sa.String(255), nullable=True),
        sa.Column('plan', sa.String(50), nullable=False, server_default='starter'),
        sa.Column('asset_limit', sa.Integer(), nullable=False, server_default='500'),
        sa.Column('stripe_customer_id', sa.String(255), nullable=True),
        sa.Column('jurisdiction', sa.String(10), nullable=False, server_default='US'),
        sa.Column('weight_profile', sa.String(50), nullable=False, server_default='usa_fedramp'),
        sa.Column('data_residency', sa.String(50), nullable=False, server_default='us-east-1'),
        sa.Column('sector', sa.String(100), nullable=False, server_default='default'),
        sa.Column('cdcs_alert_threshold', sa.Float(), nullable=False, server_default='7.0'),
        sa.Column('rea_cdcs_threshold', sa.Float(), nullable=False, server_default='6.5'),
        sa.Column('mace_config', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('enabled_frameworks', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_fedramp', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_hipaa_baa', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('soc2_compliant', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('primary_contact_email', sa.String(255), nullable=True),
        sa.Column('technical_contact_email', sa.String(255), nullable=True),
        sa.Column('security_contact_email', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('trial_ends_at', sa.DateTime(), nullable=True),
        sa.Column('settings', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('notes', sa.Text(), nullable=True),
    )
    op.create_index('ix_tenants_slug', 'tenants', ['slug'], unique=True)

    # users
    op.create_table('users',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255), nullable=True),
        sa.Column('avatar_url', sa.String(512), nullable=True),
        sa.Column('hashed_password', sa.String(255), nullable=True),
        sa.Column('sso_provider', sa.String(50), nullable=True),
        sa.Column('sso_subject', sa.String(255), nullable=True),
        sa.Column('role', sa.String(50), nullable=False, server_default='soc_analyst'),
        sa.Column('permissions', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_verified', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('mfa_enabled', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('mfa_secret', sa.String(255), nullable=True),
        sa.Column('mfa_backup_codes', sa.JSON(), nullable=True),
        sa.Column('last_login_at', sa.DateTime(), nullable=True),
        sa.Column('last_login_ip', sa.String(45), nullable=True),
        sa.Column('failed_login_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('locked_until', sa.DateTime(), nullable=True),
        sa.Column('password_reset_token', sa.String(255), nullable=True),
        sa.Column('password_reset_expires', sa.DateTime(), nullable=True),
        sa.Column('email_verify_token', sa.String(255), nullable=True),
        sa.Column('timezone', sa.String(50), nullable=False, server_default='UTC'),
        sa.Column('jurisdiction_view', sa.String(10), nullable=True),
        sa.Column('notification_prefs', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('ix_users_tenant_id', 'users', ['tenant_id'])
    op.create_index('ix_users_email', 'users', ['email'])
    op.create_unique_constraint('uq_users_tenant_email', 'users', ['tenant_id', 'email'])

    # api_keys
    op.create_table('api_keys',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('key_prefix', sa.String(20), nullable=False),
        sa.Column('key_hash', sa.String(255), nullable=False),
        sa.Column('scopes', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('ix_api_keys_tenant_id', 'api_keys', ['tenant_id'])
    op.create_index('ix_api_keys_key_hash', 'api_keys', ['key_hash'])

    # assets
    op.create_table('assets',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('canonical_id', sa.String(36), unique=True, nullable=False),
        sa.Column('hostname', sa.String(255), nullable=True),
        sa.Column('mac_address', sa.String(17), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('cloud_instance_id', sa.String(255), nullable=True),
        sa.Column('cloud_account_id', sa.String(255), nullable=True),
        sa.Column('cert_fingerprint', sa.String(512), nullable=True),
        sa.Column('serial_number', sa.String(255), nullable=True),
        sa.Column('asset_class', sa.String(50), nullable=False, server_default='unknown'),
        sa.Column('status', sa.String(50), nullable=False, server_default='active'),
        sa.Column('os', sa.String(255), nullable=True),
        sa.Column('open_ports', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('owner', sa.String(255), nullable=True),
        sa.Column('owner_email', sa.String(255), nullable=True),
        sa.Column('sector', sa.String(100), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('jurisdiction', sa.String(10), nullable=False, server_default='US'),
        sa.Column('data_classification', sa.String(50), nullable=False, server_default='internal'),
        sa.Column('is_internet_facing', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_critical_infra', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('acs_score', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('entropy_score', sa.Float(), nullable=False, server_default='0.5'),
        sa.Column('cdcs_score', sa.Float(), nullable=True),
        sa.Column('risk_level', sa.String(20), nullable=True),
        sa.Column('source_set', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('quorum_sources', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('shadow_it_flag', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('geo_velocity_flag', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('max_geo_velocity_kmh', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('last_geo_lat', sa.Float(), nullable=True),
        sa.Column('last_geo_lon', sa.Float(), nullable=True),
        sa.Column('last_geo_city', sa.String(100), nullable=True),
        sa.Column('last_geo_country', sa.String(10), nullable=True),
        sa.Column('critical_vuln_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('high_vuln_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('open_cves', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('parent_asset_id', sa.String(36), nullable=True),
        sa.Column('lineage_events', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('first_seen_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('last_seen_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('last_scored_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('raw_attributes', sa.JSON(), nullable=False, server_default='{}'),
    )
    op.create_index('ix_assets_tenant_id', 'assets', ['tenant_id'])
    op.create_index('ix_assets_tenant_status', 'assets', ['tenant_id', 'status'])
    op.create_index('ix_assets_acs', 'assets', ['tenant_id', 'acs_score'])
    op.create_index('ix_assets_hostname', 'assets', ['hostname'])
    op.create_index('ix_assets_mac', 'assets', ['mac_address'])
    op.create_index('ix_assets_cloud', 'assets', ['cloud_instance_id'])

    # asset_sources
    op.create_table('asset_sources',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('asset_id', sa.String(36), sa.ForeignKey('assets.id'), nullable=False),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('source_name', sa.String(100), nullable=False),
        sa.Column('source_id', sa.String(255), nullable=False),
        sa.Column('source_confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('raw_data', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('last_seen_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('ix_asset_sources_asset_id', 'asset_sources', ['asset_id'])
    op.create_index('ix_asset_sources_tenant_id', 'asset_sources', ['tenant_id'])

    # vulnerabilities (master — shared across tenants)
    op.create_table('vulnerabilities',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('cve_id', sa.String(30), unique=True, nullable=False),
        sa.Column('cvss_v3', sa.Float(), nullable=True),
        sa.Column('cvss_v3_vector', sa.String(255), nullable=True),
        sa.Column('severity', sa.String(20), nullable=True),
        sa.Column('epss_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('epss_percentile', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('epss_updated_at', sa.DateTime(), nullable=True),
        sa.Column('exploit_public', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('exploit_poc', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('exploit_active', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('cisa_kev', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('references', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('affected_products', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('mitre_technique_ids', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('patch_available', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('patch_url', sa.String(512), nullable=True),
        sa.Column('published_at', sa.DateTime(), nullable=True),
        sa.Column('modified_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('ix_vulnerabilities_cve_id', 'vulnerabilities', ['cve_id'], unique=True)

    # vulnerability_findings (per tenant, per asset)
    op.create_table('vulnerability_findings',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('asset_id', sa.String(36), sa.ForeignKey('assets.id'), nullable=False),
        sa.Column('vulnerability_id', sa.String(36), sa.ForeignKey('vulnerabilities.id'), nullable=False),
        sa.Column('cve_id', sa.String(30), nullable=False),
        sa.Column('exposure', sa.String(50), nullable=False, server_default='internal'),
        sa.Column('exploit_status', sa.String(50), nullable=False, server_default='no_exploit_known'),
        sa.Column('affected_component', sa.String(255), nullable=True),
        sa.Column('sla_days_critical', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('sla_days_high', sa.Integer(), nullable=False, server_default='7'),
        sa.Column('sla_breach_at', sa.DateTime(), nullable=True),
        sa.Column('sla_breached', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('status', sa.String(50), nullable=False, server_default='open'),
        sa.Column('assigned_to', sa.String(255), nullable=True),
        sa.Column('remediation_notes', sa.Text(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('discovered_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('ix_vuln_findings_tenant_id', 'vulnerability_findings', ['tenant_id'])
    op.create_index('ix_vuln_findings_asset_id', 'vulnerability_findings', ['asset_id'])
    op.create_index('ix_vuln_findings_cve_id', 'vulnerability_findings', ['cve_id'])

    # regulatory_evidence
    op.create_table('regulatory_evidence',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('incident_ref', sa.String(50), nullable=False),
        sa.Column('dfa_state_log', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('chain_of_custody_hash', sa.String(64), nullable=False),
        sa.Column('cdcs_score', sa.Float(), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('frameworks_triggered', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('jurisdictions', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('reporting_deadlines', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('cert_in_reference', sa.String(100), nullable=True),
        sa.Column('aecert_reference', sa.String(100), nullable=True),
        sa.Column('cert_in_draft', sa.Text(), nullable=True),
        sa.Column('dpdp_draft', sa.Text(), nullable=True),
        sa.Column('rbi_draft', sa.Text(), nullable=True),
        sa.Column('gdpr_art33_draft', sa.Text(), nullable=True),
        sa.Column('nis2_draft', sa.Text(), nullable=True),
        sa.Column('dora_draft', sa.Text(), nullable=True),
        sa.Column('fedramp_sir_draft', sa.Text(), nullable=True),
        sa.Column('sec_8k_draft', sa.Text(), nullable=True),
        sa.Column('hipaa_draft', sa.Text(), nullable=True),
        sa.Column('pipeda_draft', sa.Text(), nullable=True),
        sa.Column('nesa_draft', sa.Text(), nullable=True),
        sa.Column('status', sa.String(20), nullable=False, server_default='open'),
        sa.Column('sla_breached', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('submitted_frameworks', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('asset_attributes', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('detected_at', sa.DateTime(), nullable=False),
        sa.Column('evidenced_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('ix_regulatory_evidence_tenant_id', 'regulatory_evidence', ['tenant_id'])

    # incidents
    op.create_table('incidents',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('asset_id', sa.String(36), sa.ForeignKey('assets.id'), nullable=True),
        sa.Column('incident_ref', sa.String(50), unique=True, nullable=False),
        sa.Column('title', sa.String(512), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('cdcs_score', sa.Float(), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('status', sa.String(50), nullable=False, server_default='open'),
        sa.Column('v_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('e_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('i_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('n_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('c_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('t_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('sector_multiplier', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('blast_radius_multiplier', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('kill_chain_multiplier', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('kill_chain_stage', sa.String(50), nullable=True),
        sa.Column('dominant_domain', sa.String(50), nullable=True),
        sa.Column('lateral_hop_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('regulatory_evidence_id', sa.String(36), sa.ForeignKey('regulatory_evidence.id'), nullable=True),
        sa.Column('jurisdictions', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('frameworks_triggered', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('assigned_to', sa.String(255), nullable=True),
        sa.Column('responders', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('response_notes', sa.Text(), nullable=True),
        sa.Column('timeline', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('confirmed_true_positive', sa.Boolean(), nullable=True),
        sa.Column('feedback_at', sa.DateTime(), nullable=True),
        sa.Column('feedback_by', sa.String(255), nullable=True),
        sa.Column('detected_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
        sa.Column('contained_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('ix_incidents_tenant_id', 'incidents', ['tenant_id'])
    op.create_index('ix_incidents_severity', 'incidents', ['tenant_id', 'severity'])
    op.create_index('ix_incidents_status', 'incidents', ['tenant_id', 'status'])
    op.create_index('ix_incidents_detected_at', 'incidents', ['tenant_id', 'detected_at'])

    # subscriptions
    op.create_table('subscriptions',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('stripe_subscription_id', sa.String(255), unique=True, nullable=True),
        sa.Column('stripe_price_id', sa.String(255), nullable=True),
        sa.Column('plan_name', sa.String(100), nullable=False),
        sa.Column('status', sa.String(50), nullable=False, server_default='trialing'),
        sa.Column('asset_limit', sa.Integer(), nullable=False, server_default='500'),
        sa.Column('price_per_asset_usd', sa.Float(), nullable=True),
        sa.Column('current_period_start', sa.DateTime(), nullable=True),
        sa.Column('current_period_end', sa.DateTime(), nullable=True),
        sa.Column('trial_end', sa.DateTime(), nullable=True),
        sa.Column('canceled_at', sa.DateTime(), nullable=True),
        sa.Column('assets_used', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('features', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('ix_subscriptions_tenant_id', 'subscriptions', ['tenant_id'])

    # usage_records
    op.create_table('usage_records',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('subscription_id', sa.String(36), sa.ForeignKey('subscriptions.id'), nullable=False),
        sa.Column('metric', sa.String(100), nullable=False),
        sa.Column('quantity', sa.Integer(), nullable=False),
        sa.Column('recorded_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('stripe_usage_record_id', sa.String(255), nullable=True),
    )
    op.create_index('ix_usage_records_tenant_id', 'usage_records', ['tenant_id'])

    # connector_configs
    op.create_table('connector_configs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('connector_type', sa.String(50), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('status', sa.String(50), nullable=False, server_default='testing'),
        sa.Column('base_url', sa.String(512), nullable=True),
        sa.Column('client_id', sa.String(512), nullable=True),
        sa.Column('client_secret_encrypted', sa.Text(), nullable=True),
        sa.Column('api_key_encrypted', sa.Text(), nullable=True),
        sa.Column('sync_enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('sync_interval_minutes', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('last_sync_at', sa.DateTime(), nullable=True),
        sa.Column('last_sync_status', sa.String(50), nullable=True),
        sa.Column('last_sync_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('provides_assets', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('provides_vulns', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('provides_events', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('provides_threat_intel', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('field_mapping', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('filters', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('ix_connector_configs_tenant_id', 'connector_configs', ['tenant_id'])

    # audit_logs (immutable)
    op.create_table('audit_logs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('user_id', sa.String(36), nullable=True),
        sa.Column('user_email', sa.String(255), nullable=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(100), nullable=True),
        sa.Column('resource_id', sa.String(36), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(512), nullable=True),
        sa.Column('old_values', sa.JSON(), nullable=True),
        sa.Column('new_values', sa.JSON(), nullable=True),
        # Column is named metadata_json (the Python attribute is `extra`) because
        # `metadata` is reserved by SQLAlchemy's DeclarativeBase.
        sa.Column('metadata_json', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('success', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('ix_audit_logs_tenant_id', 'audit_logs', ['tenant_id'])
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])
    op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'])


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('connector_configs')
    op.drop_table('usage_records')
    op.drop_table('subscriptions')
    op.drop_table('incidents')
    op.drop_table('regulatory_evidence')
    op.drop_table('vulnerability_findings')
    op.drop_table('vulnerabilities')
    op.drop_table('asset_sources')
    op.drop_table('assets')
    op.drop_table('api_keys')
    op.drop_table('users')
    op.drop_table('tenants')
