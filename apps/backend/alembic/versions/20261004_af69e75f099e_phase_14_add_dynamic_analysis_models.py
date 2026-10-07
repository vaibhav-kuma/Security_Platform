"""phase_14_add_dynamic_analysis_models

Revision ID: af69e75f099e
Revises: e797863fe107
Create Date: 2026-10-04 21:30:17.099157
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'af69e75f099e'
down_revision = 'e797863fe107'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create emulator_profiles table
    op.create_table('emulator_profiles',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('avd_name', sa.String(length=255), nullable=False),
        sa.Column('api_level', sa.Integer(), nullable=False),
        sa.Column('abi', sa.String(length=64), nullable=False),
        sa.Column('ram_mb', sa.Integer(), nullable=False, default=2048),
        sa.Column('storage_mb', sa.Integer(), nullable=False, default=4096),
        sa.Column('proxy_host', sa.String(length=255), nullable=True),
        sa.Column('proxy_port', sa.Integer(), nullable=True),
        sa.Column('gpu_enabled', sa.Boolean(), nullable=False, default=True),
        sa.Column('camera_enabled', sa.Boolean(), nullable=False, default=False),
        sa.Column('gps_enabled', sa.Boolean(), nullable=False, default=False),
        sa.Column('max_cpu_percent', sa.Integer(), nullable=False, default=80),
        sa.Column('max_memory_mb', sa.Integer(), nullable=False, default=4096),
        sa.Column('max_execution_time_seconds', sa.Integer(), nullable=False, default=3600),
        sa.Column('network_policy', sa.String(length=64), nullable=False, default='proxy_only'),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_emulator_profiles')),
        sa.UniqueConstraint('name', name=op.f('uq_emulator_profiles_name'))
    )
    op.create_index(op.f('ix_emulator_profiles_name'), 'emulator_profiles', ['name'], unique=True)

    # Create emulator_instances table
    op.create_table('emulator_instances',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('profile_id', sa.Uuid(), nullable=False),
        sa.Column('status', sa.Enum('stopped', 'starting', 'running', 'stopping', 'error', name='emulatorstatus'), nullable=False, default='stopped'),
        sa.Column('pid', sa.Integer(), nullable=True),
        sa.Column('adb_port', sa.Integer(), nullable=True),
        sa.Column('vnc_port', sa.Integer(), nullable=True),
        sa.Column('cpu_percent', sa.Float(), nullable=False, default=0.0),
        sa.Column('memory_mb', sa.Integer(), nullable=False, default=0),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('stopped_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.ForeignKeyConstraint(['profile_id'], ['emulator_profiles.id'], name=op.f('fk_emulator_instances_profile_id_emulator_profiles'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_emulator_instances'))
    )
    op.create_index(op.f('ix_emulator_instances_profile_id'), 'emulator_instances', ['profile_id'], unique=False)
    op.create_index(op.f('ix_emulator_instances_status'), 'emulator_instances', ['status'], unique=False)

    # Create dynamic_analysis_runs table
    op.create_table('dynamic_analysis_runs',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('scan_id', sa.Uuid(), nullable=False),
        sa.Column('emulator_instance_id', sa.Uuid(), nullable=True),
        sa.Column('apk_file_id', sa.Uuid(), nullable=False),
        sa.Column('test_context', sa.String(length=64), nullable=False, default='default'),
        sa.Column('network_policy', sa.String(length=64), nullable=False, default='proxy_only'),
        sa.Column('proxy_configuration', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.Column('frida_scripts', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default=[]),
        sa.Column('resource_limits', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.Column('status', sa.String(length=32), nullable=False, default='pending'),
        sa.Column('events_captured', sa.Integer(), nullable=False, default=0),
        sa.Column('network_observations', sa.Integer(), nullable=False, default=0),
        sa.Column('file_operations', sa.Integer(), nullable=False, default=0),
        sa.Column('ipc_events', sa.Integer(), nullable=False, default=0),
        sa.Column('crypto_operations', sa.Integer(), nullable=False, default=0),
        sa.Column('evidence_artifacts', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.Column('correlated_static_findings', sa.Integer(), nullable=False, default=0),
        sa.Column('correlated_api_findings', sa.Integer(), nullable=False, default=0),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.ForeignKeyConstraint(['apk_file_id'], ['apk_files.id'], name=op.f('fk_dynamic_analysis_runs_apk_file_id_apk_files'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['emulator_instance_id'], ['emulator_instances.id'], name=op.f('fk_dynamic_analysis_runs_emulator_instance_id_emulator_instances'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], name=op.f('fk_dynamic_analysis_runs_scan_id_scans'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_dynamic_analysis_runs'))
    )
    op.create_index(op.f('ix_dynamic_analysis_runs_scan_id'), 'dynamic_analysis_runs', ['scan_id'], unique=False)
    op.create_index(op.f('ix_dynamic_analysis_runs_emulator_instance_id'), 'dynamic_analysis_runs', ['emulator_instance_id'], unique=False)
    op.create_index(op.f('ix_dynamic_analysis_runs_apk_file_id'), 'dynamic_analysis_runs', ['apk_file_id'], unique=False)
    op.create_index(op.f('ix_dynamic_analysis_runs_status'), 'dynamic_analysis_runs', ['status'], unique=False)

    # Create runtime_events table
    op.create_table('runtime_events',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('analysis_run_id', sa.Uuid(), nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('event_subtype', sa.String(length=128), nullable=True),
        sa.Column('source_package', sa.String(length=255), nullable=True),
        sa.Column('source_class', sa.String(length=512), nullable=True),
        sa.Column('source_method', sa.String(length=256), nullable=True),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('raw_data', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.Column('severity', sa.String(length=16), nullable=False, default='info'),
        sa.Column('confidence', sa.String(length=16), nullable=False, default='medium'),
        sa.Column('mastg_references', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default=[]),
        sa.Column('masvs_references', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default=[]),
        sa.Column('correlated_static_finding_id', sa.Uuid(), nullable=True),
        sa.Column('correlated_api_finding_id', sa.Uuid(), nullable=True),
        sa.Column('evidence_artifacts', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.Column('stack_trace', sa.Text(), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.ForeignKeyConstraint(['analysis_run_id'], ['dynamic_analysis_runs.id'], name=op.f('fk_runtime_events_analysis_run_id_dynamic_analysis_runs'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['correlated_static_finding_id'], ['findings.id'], name=op.f('fk_runtime_events_correlated_static_finding_id_findings'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['correlated_api_finding_id'], ['findings.id'], name=op.f('fk_runtime_events_correlated_api_finding_id_findings'), ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_runtime_events'))
    )
    op.create_index(op.f('ix_runtime_events_analysis_run_id'), 'runtime_events', ['analysis_run_id'], unique=False)
    op.create_index(op.f('ix_runtime_events_event_type'), 'runtime_events', ['event_type'], unique=False)
    op.create_index(op.f('ix_runtime_events_source_package'), 'runtime_events', ['source_package'], unique=False)

    # Create network_observations table
    op.create_table('network_observations',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('analysis_run_id', sa.Uuid(), nullable=False),
        sa.Column('protocol', sa.String(length=16), nullable=False),
        sa.Column('direction', sa.String(length=16), nullable=False),
        sa.Column('source_package', sa.String(length=255), nullable=True),
        sa.Column('source_ip', sa.String(length=64), nullable=True),
        sa.Column('source_port', sa.Integer(), nullable=True),
        sa.Column('destination_host', sa.String(length=512), nullable=False),
        sa.Column('destination_ip', sa.String(length=64), nullable=True),
        sa.Column('destination_port', sa.Integer(), nullable=True),
        sa.Column('http_method', sa.String(length=16), nullable=True),
        sa.Column('http_path', sa.String(length=2048), nullable=True),
        sa.Column('http_status', sa.Integer(), nullable=True),
        sa.Column('request_headers', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.Column('response_headers', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.Column('request_body', sa.Text(), nullable=True),
        sa.Column('response_body', sa.Text(), nullable=True),
        sa.Column('tls_version', sa.String(length=32), nullable=True),
        sa.Column('cipher_suite', sa.String(length=128), nullable=True),
        sa.Column('certificate_pinned', sa.Boolean(), nullable=False, default=False),
        sa.Column('certificate_valid', sa.Boolean(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('bytes_sent', sa.Integer(), nullable=True),
        sa.Column('bytes_received', sa.Integer(), nullable=True),
        sa.Column('is_cleartext', sa.Boolean(), nullable=False, default=False),
        sa.Column('is_suspicious', sa.Boolean(), nullable=False, default=False),
        sa.Column('suspicious_reason', sa.Text(), nullable=True),
        sa.Column('mastg_references', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default=[]),
        sa.Column('masvs_references', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default=[]),
        sa.Column('pcap_file', sa.String(length=1024), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.ForeignKeyConstraint(['analysis_run_id'], ['dynamic_analysis_runs.id'], name=op.f('fk_network_observations_analysis_run_id_dynamic_analysis_runs'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_network_observations'))
    )
    op.create_index(op.f('ix_network_observations_analysis_run_id'), 'network_observations', ['analysis_run_id'], unique=False)
    op.create_index(op.f('ix_network_observations_protocol'), 'network_observations', ['protocol'], unique=False)
    op.create_index(op.f('ix_network_observations_destination_host'), 'network_observations', ['destination_host'], unique=False)
    op.create_index(op.f('ix_network_observations_source_package'), 'network_observations', ['source_package'], unique=False)

    # Create file_observations table
    op.create_table('file_observations',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('analysis_run_id', sa.Uuid(), nullable=False),
        sa.Column('operation', sa.String(length=32), nullable=False),
        sa.Column('file_path', sa.String(length=2048), nullable=False),
        sa.Column('file_size', sa.Integer(), nullable=True),
        sa.Column('file_hash', sa.String(length=64), nullable=True),
        sa.Column('mime_type', sa.String(length=128), nullable=True),
        sa.Column('source_package', sa.String(length=255), nullable=True),
        sa.Column('source_class', sa.String(length=512), nullable=True),
        sa.Column('source_method', sa.String(length=256), nullable=True),
        sa.Column('old_permissions', sa.String(length=16), nullable=True),
        sa.Column('new_permissions', sa.String(length=16), nullable=True),
        sa.Column('contains_sensitive_data', sa.Boolean(), nullable=False, default=False),
        sa.Column('sensitive_patterns', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default=[]),
        sa.Column('mastg_references', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default=[]),
        sa.Column('masvs_references', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default=[]),
        sa.Column('file_snapshot', sa.String(length=1024), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.ForeignKeyConstraint(['analysis_run_id'], ['dynamic_analysis_runs.id'], name=op.f('fk_file_observations_analysis_run_id_dynamic_analysis_runs'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_file_observations'))
    )
    op.create_index(op.f('ix_file_observations_analysis_run_id'), 'file_observations', ['analysis_run_id'], unique=False)
    op.create_index(op.f('ix_file_observations_operation'), 'file_observations', ['operation'], unique=False)
    op.create_index(op.f('ix_file_observations_file_path'), 'file_observations', ['file_path'], unique=False)
    op.create_index(op.f('ix_file_observations_source_package'), 'file_observations', ['source_package'], unique=False)

    # Create ipc_observations table
    op.create_table('ipc_observations',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('analysis_run_id', sa.Uuid(), nullable=False),
        sa.Column('ipc_type', sa.String(length=32), nullable=False),
        sa.Column('source_package', sa.String(length=255), nullable=True),
        sa.Column('source_component', sa.String(length=512), nullable=True),
        sa.Column('destination_package', sa.String(length=255), nullable=True),
        sa.Column('destination_component', sa.String(length=512), nullable=True),
        sa.Column('action', sa.String(length=256), nullable=True),
        sa.Column('categories', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default=[]),
        sa.Column('data_uri', sa.String(length=2048), nullable=True),
        sa.Column('mime_type', sa.String(length=128), nullable=True),
        sa.Column('extras', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.Column('flags', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default=[]),
        sa.Column('exported', sa.Boolean(), nullable=True),
        sa.Column('permission_required', sa.String(length=256), nullable=True),
        sa.Column('mastg_references', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default=[]),
        sa.Column('masvs_references', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default=[]),
        sa.Column('intent_dump', sa.Text(), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.ForeignKeyConstraint(['analysis_run_id'], ['dynamic_analysis_runs.id'], name=op.f('fk_ipc_observations_analysis_run_id_dynamic_analysis_runs'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_ipc_observations'))
    )
    op.create_index(op.f('ix_ipc_observations_analysis_run_id'), 'ipc_observations', ['analysis_run_id'], unique=False)
    op.create_index(op.f('ix_ipc_observations_ipc_type'), 'ipc_observations', ['ipc_type'], unique=False)
    op.create_index(op.f('ix_ipc_observations_source_package'), 'ipc_observations', ['source_package'], unique=False)
    op.create_index(op.f('ix_ipc_observations_destination_package'), 'ipc_observations', ['destination_package'], unique=False)

    # Create dynamic_analysis_evidence table
    op.create_table('dynamic_analysis_evidence',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('analysis_run_id', sa.Uuid(), nullable=False),
        sa.Column('evidence_type', sa.String(length=64), nullable=False),
        sa.Column('storage', sa.String(length=16), nullable=False, default='inline'),
        sa.Column('content', sa.Text(), nullable=True),
        sa.Column('object_key', sa.String(length=1024), nullable=True),
        sa.Column('sha256', sa.String(length=64), nullable=True),
        sa.Column('redacted', sa.Boolean(), nullable=False, default=False),
        sa.Column('redacted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('tags', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default=[]),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, default={}),
        sa.ForeignKeyConstraint(['analysis_run_id'], ['dynamic_analysis_runs.id'], name=op.f('fk_dynamic_analysis_evidence_analysis_run_id_dynamic_analysis_runs'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_dynamic_analysis_evidence'))
    )
    op.create_index(op.f('ix_dynamic_analysis_evidence_analysis_run_id'), 'dynamic_analysis_evidence', ['analysis_run_id'], unique=False)
    op.create_index(op.f('ix_dynamic_analysis_evidence_evidence_type'), 'dynamic_analysis_evidence', ['evidence_type'], unique=False)

    # Add SecurityEventType enum values for dynamic analysis
    # Note: This would require a separate migration for enum values


def downgrade() -> None:
    op.drop_index(op.f('ix_dynamic_analysis_evidence_evidence_type'), table_name='dynamic_analysis_evidence')
    op.drop_index(op.f('ix_dynamic_analysis_evidence_analysis_run_id'), table_name='dynamic_analysis_evidence')
    op.drop_table('dynamic_analysis_evidence')

    op.drop_index(op.f('ix_ipc_observations_destination_package'), table_name='ipc_observations')
    op.drop_index(op.f('ix_ipc_observations_source_package'), table_name='ipc_observations')
    op.drop_index(op.f('ix_ipc_observations_ipc_type'), table_name='ipc_observations')
    op.drop_index(op.f('ix_ipc_observations_analysis_run_id'), table_name='ipc_observations')
    op.drop_table('ipc_observations')

    op.drop_index(op.f('ix_file_observations_source_package'), table_name='file_observations')
    op.drop_index(op.f('ix_file_observations_file_path'), table_name='file_observations')
    op.drop_index(op.f('ix_file_observations_operation'), table_name='file_observations')
    op.drop_index(op.f('ix_file_observations_analysis_run_id'), table_name='file_observations')
    op.drop_table('file_observations')

    op.drop_index(op.f('ix_network_observations_source_package'), table_name='network_observations')
    op.drop_index(op.f('ix_network_observations_destination_host'), table_name='network_observations')
    op.drop_index(op.f('ix_network_observations_protocol'), table_name='network_observations')
    op.drop_index(op.f('ix_network_observations_analysis_run_id'), table_name='network_observations')
    op.drop_table('network_observations')

    op.drop_index(op.f('ix_runtime_events_source_package'), table_name='runtime_events')
    op.drop_index(op.f('ix_runtime_events_event_type'), table_name='runtime_events')
    op.drop_index(op.f('ix_runtime_events_analysis_run_id'), table_name='runtime_events')
    op.drop_table('runtime_events')

    op.drop_index(op.f('ix_dynamic_analysis_runs_status'), table_name='dynamic_analysis_runs')
    op.drop_index(op.f('ix_dynamic_analysis_runs_apk_file_id'), table_name='dynamic_analysis_runs')
    op.drop_index(op.f('ix_dynamic_analysis_runs_emulator_instance_id'), table_name='dynamic_analysis_runs')
    op.drop_index(op.f('ix_dynamic_analysis_runs_scan_id'), table_name='dynamic_analysis_runs')
    op.drop_table('dynamic_analysis_runs')

    op.drop_index(op.f('ix_emulator_instances_status'), table_name='emulator_instances')
    op.drop_index(op.f('ix_emulator_instances_profile_id'), table_name='emulator_instances')
    op.drop_table('emulator_instances')

    op.drop_index(op.f('ix_emulator_profiles_name'), table_name='emulator_profiles')
    op.drop_table('emulator_profiles')