from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta
import json

from .models import (
    IntelligenceUser, Department, Source, IntelligenceReport, Target, 
    Operation, OperationAssignment, Incident, SecureMessage, MessageReadStatus,
    CollectionRequirement, ThreatAssessment, Equipment, AuditLog
)


# Custom Admin Base Class with Security Features
class SecureModelAdmin(admin.ModelAdmin):
    """Base admin class with security enhancements"""
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # Add user-based filtering if needed
        if not request.user.is_superuser:
            # Add department-based filtering for non-superusers
            if hasattr(request.user, 'department'):
                return qs.filter(department=request.user.department)
        return qs
    
    def save_model(self, request, obj, form, change):
        """Override to add audit logging"""
        action = 'UPDATE' if change else 'CREATE'
        super().save_model(request, obj, form, change)
        
        # Create audit log entry
        AuditLog.objects.create(
            user=request.user,
            action=action,
            resource_type=obj.__class__.__name__,
            resource_id=str(obj.pk),
            description=f"{action} {obj.__class__.__name__}: {obj}",
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            classification_level=getattr(obj, 'classification', '')
        )
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


# Custom UserAdmin for Intelligence Personnel
@admin.register(IntelligenceUser)
class IntelligenceUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'employee_id', 
                   'clearance_level', 'role', 'department', 'is_active_duty', 
                   'security_clearance_status')
    list_filter = ('clearance_level', 'role', 'department', 'is_active_duty', 
                  'security_clearance_expiry', 'date_joined')
    search_fields = ('username', 'email', 'first_name', 'last_name', 'employee_id')
    ordering = ('username',)
    
    fieldsets = UserAdmin.fieldsets + (
        ('Intelligence Profile', {
            'fields': ('employee_id', 'clearance_level', 'role', 'department', 
                      'phone', 'emergency_contact', 'is_active_duty', 
                      'security_clearance_expiry')
        }),
    )
    
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Intelligence Profile', {
            'fields': ('employee_id', 'clearance_level', 'role', 'department', 
                      'phone', 'emergency_contact', 'is_active_duty',
                      'security_clearance_expiry')
        }),
    )
    
    def security_clearance_status(self, obj):
        if obj.security_clearance_expiry:
            days_until_expiry = (obj.security_clearance_expiry - timezone.now().date()).days
            if days_until_expiry < 0:
                return format_html('<span style="color: red;">EXPIRED</span>')
            elif days_until_expiry < 30:
                return format_html('<span style="color: orange;">Expires in {} days</span>', days_until_expiry)
            else:
                return format_html('<span style="color: green;">Valid</span>')
        return 'No expiry set'
    
    security_clearance_status.short_description = 'Clearance Status'


@admin.register(Department)
class DepartmentAdmin(SecureModelAdmin):
    list_display = ('code', 'name', 'head', 'parent_department', 'personnel_count', 'created_at')
    list_filter = ('parent_department', 'created_at')
    search_fields = ('name', 'code', 'description')
    raw_id_fields = ('head', 'parent_department')
    
    def personnel_count(self, obj):
        count = obj.intelligenceuser_set.count()
        url = reverse('admin:myapplication_intelligenceuser_changelist') + f'?department__exact={obj.id}'
        return format_html('<a href="{}">{} personnel</a>', url, count)
    
    personnel_count.short_description = 'Personnel'


@admin.register(Source)
class SourceAdmin(SecureModelAdmin):
    list_display = ('source_id', 'codename', 'source_type', 'reliability_level', 
                   'handler', 'location', 'is_active', 'last_contact_status')
    list_filter = ('source_type', 'reliability_level', 'is_active', 'recruitment_date')
    search_fields = ('source_id', 'codename', 'location')
    raw_id_fields = ('handler',)
    date_hierarchy = 'recruitment_date'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('source_id', 'codename', 'source_type', 'reliability_level')
        }),
        ('Assignment', {
            'fields': ('handler', 'location', 'contact_method', 'is_active')
        }),
        ('Timeline', {
            'fields': ('recruitment_date', 'last_contact')
        }),
        ('Notes', {
            'fields': ('notes',),
            'classes': ('collapse',)
        })
    )
    
    def last_contact_status(self, obj):
        if obj.last_contact:
            days_ago = (timezone.now() - obj.last_contact).days
            if days_ago == 0:
                return format_html('<span style="color: green;">Today</span>')
            elif days_ago < 7:
                return format_html('<span style="color: blue;">{} days ago</span>', days_ago)
            elif days_ago < 30:
                return format_html('<span style="color: orange;">{} days ago</span>', days_ago)
            else:
                return format_html('<span style="color: red;">{} days ago</span>', days_ago)
        return format_html('<span style="color: gray;">Never</span>')
    
    last_contact_status.short_description = 'Last Contact'


@admin.register(IntelligenceReport)
class IntelligenceReportAdmin(SecureModelAdmin):
    list_display = ('report_id', 'title', 'report_type', 'classification_badge', 
                   'author', 'status', 'confidence_level', 'created_at')
    list_filter = ('report_type', 'classification', 'status', 'confidence_level', 
                  'geographic_focus', 'created_at')
    search_fields = ('report_id', 'title', 'content', 'tags')
    raw_id_fields = ('author', 'reviewer', 'source')
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Report Information', {
            'fields': ('report_id', 'title', 'report_type', 'classification')
        }),
        ('Personnel', {
            'fields': ('author', 'reviewer', 'source')
        }),
        ('Content', {
            'fields': ('executive_summary', 'content', 'key_findings', 'recommendations')
        }),
        ('Metadata', {
            'fields': ('confidence_level', 'geographic_focus', 'tags', 'status')
        }),
        ('Timeline', {
            'fields': ('dissemination_date',),
            'classes': ('collapse',)
        })
    )
    
    def classification_badge(self, obj):
        colors = {
            'U': 'green',
            'C': 'blue', 
            'S': 'orange',
            'TS': 'red'
        }
        color = colors.get(obj.classification, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            color, obj.get_classification_display()
        )
    
    classification_badge.short_description = 'Classification'


@admin.register(Target)
class TargetAdmin(SecureModelAdmin):
    list_display = ('target_id', 'name', 'target_type', 'threat_level_badge', 
                   'priority_score', 'assigned_analyst', 'is_active')
    list_filter = ('target_type', 'threat_level', 'nationality', 'is_active', 
                  'priority_score')
    search_fields = ('target_id', 'name', 'alias', 'description')
    raw_id_fields = ('assigned_analyst',)
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('target_id', 'name', 'alias', 'target_type')
        }),
        ('Assessment', {
            'fields': ('threat_level', 'priority_score', 'assigned_analyst', 'is_active')
        }),
        ('Details', {
            'fields': ('description', 'location', 'nationality', 'affiliations')
        }),
        ('Attributes', {
            'fields': ('key_attributes',),
            'classes': ('collapse',)
        })
    )
    
    def threat_level_badge(self, obj):
        colors = {
            'LOW': 'green',
            'MEDIUM': 'blue',
            'HIGH': 'orange', 
            'CRITICAL': 'red'
        }
        color = colors.get(obj.threat_level, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            color, obj.threat_level
        )
    
    threat_level_badge.short_description = 'Threat Level'


class OperationAssignmentInline(admin.TabularInline):
    model = OperationAssignment
    extra = 1
    raw_id_fields = ('personnel',)


@admin.register(Operation)
class OperationAdmin(SecureModelAdmin):
    list_display = ('operation_id', 'codename', 'operation_type', 'classification_badge',
                   'commanding_officer', 'status', 'start_date', 'duration')
    list_filter = ('operation_type', 'classification', 'status', 'start_date')
    search_fields = ('operation_id', 'codename', 'objectives', 'description')
    raw_id_fields = ('commanding_officer',)
    date_hierarchy = 'start_date'
    inlines = [OperationAssignmentInline]
    
    fieldsets = (
        ('Operation Details', {
            'fields': ('operation_id', 'codename', 'operation_type', 'classification')
        }),
        ('Command', {
            'fields': ('commanding_officer', 'status')
        }),
        ('Mission', {
            'fields': ('objectives', 'description', 'location')
        }),
        ('Timeline', {
            'fields': ('start_date', 'end_date')
        }),
        ('Planning', {
            'fields': ('budget', 'risk_assessment', 'success_criteria'),
            'classes': ('collapse',)
        })
    )
    
    def classification_badge(self, obj):
        colors = {'U': 'green', 'C': 'blue', 'S': 'orange', 'TS': 'red'}
        color = colors.get(obj.classification, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            color, obj.get_classification_display()
        )
    
    def duration(self, obj):
        if obj.end_date:
            duration = obj.end_date - obj.start_date
            return f"{duration.days} days"
        elif obj.status == 'ACTIVE':
            duration = timezone.now() - obj.start_date
            return f"{duration.days} days (ongoing)"
        return "Not specified"
    
    classification_badge.short_description = 'Classification'
    duration.short_description = 'Duration'


@admin.register(Incident)
class IncidentAdmin(SecureModelAdmin):
    list_display = ('incident_id', 'title', 'incident_type', 'severity_badge',
                   'reported_by', 'investigating_officer', 'is_resolved', 'date_occurred')
    list_filter = ('incident_type', 'severity', 'is_resolved', 'date_occurred')
    search_fields = ('incident_id', 'title', 'description')
    raw_id_fields = ('reported_by', 'investigating_officer', 'related_operation')
    filter_horizontal = ('related_targets',)
    date_hierarchy = 'date_occurred'
    
    fieldsets = (
        ('Incident Information', {
            'fields': ('incident_id', 'title', 'incident_type', 'severity')
        }),
        ('Personnel', {
            'fields': ('reported_by', 'investigating_officer')
        }),
        ('Details', {
            'fields': ('description', 'location', 'date_occurred')
        }),
        ('Related Items', {
            'fields': ('related_operation', 'related_targets')
        }),
        ('Assessment & Response', {
            'fields': ('impact_assessment', 'response_actions', 'lessons_learned')
        }),
        ('Resolution', {
            'fields': ('is_resolved', 'resolution_date')
        })
    )
    
    def severity_badge(self, obj):
        colors = {
            'LOW': 'green',
            'MEDIUM': 'blue',
            'HIGH': 'orange',
            'CRITICAL': 'red'
        }
        color = colors.get(obj.severity, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            color, obj.severity
        )
    
    severity_badge.short_description = 'Severity'


class MessageReadStatusInline(admin.TabularInline):
    model = MessageReadStatus
    extra = 0
    readonly_fields = ('recipient', 'read_at')


@admin.register(SecureMessage)
class SecureMessageAdmin(SecureModelAdmin):
    list_display = ('message_id_short', 'subject', 'sender', 'classification_badge',
                   'priority', 'recipients_count', 'sent_at')
    list_filter = ('classification', 'priority', 'is_encrypted', 'sent_at')
    search_fields = ('subject', 'content', 'sender__username')
    raw_id_fields = ('sender',)
    filter_horizontal = ('recipients',)
    inlines = [MessageReadStatusInline]
    
    fieldsets = (
        ('Message Details', {
            'fields': ('subject', 'content', 'classification', 'priority')
        }),
        ('Recipients', {
            'fields': ('sender', 'recipients')
        }),
        ('Security', {
            'fields': ('is_encrypted', 'read_receipt_required', 'expires_at')
        })
    )
    
    def message_id_short(self, obj):
        return str(obj.message_id)[:8] + '...'
    
    def classification_badge(self, obj):
        colors = {'U': 'green', 'C': 'blue', 'S': 'orange', 'TS': 'red'}
        color = colors.get(obj.classification, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            color, obj.get_classification_display()
        )
    
    def recipients_count(self, obj):
        return obj.recipients.count()
    
    message_id_short.short_description = 'Message ID'
    classification_badge.short_description = 'Classification'
    recipients_count.short_description = 'Recipients'


@admin.register(CollectionRequirement)
class CollectionRequirementAdmin(SecureModelAdmin):
    list_display = ('requirement_id', 'title', 'requirement_type', 'priority_level',
                   'requestor', 'assigned_collector', 'status', 'due_date')
    list_filter = ('requirement_type', 'priority_level', 'status', 'due_date')
    search_fields = ('requirement_id', 'title', 'description')
    raw_id_fields = ('requestor', 'assigned_collector', 'target')
    date_hierarchy = 'due_date'
    
    fieldsets = (
        ('Requirement Information', {
            'fields': ('requirement_id', 'title', 'requirement_type', 'priority_level')
        }),
        ('Assignment', {
            'fields': ('requestor', 'assigned_collector', 'target')
        }),
        ('Details', {
            'fields': ('description', 'justification', 'geographic_focus')
        }),
        ('Collection', {
            'fields': ('collection_methods', 'due_date', 'status')
        }),
        ('Completion', {
            'fields': ('satisfied_date',),
            'classes': ('collapse',)
        })
    )


@admin.register(ThreatAssessment)
class ThreatAssessmentAdmin(SecureModelAdmin):
    list_display = ('assessment_id', 'title', 'target', 'threat_level_badge',
                   'risk_score_display', 'analyst', 'confidence_level', 'valid_until')
    list_filter = ('assessment_type', 'threat_level', 'confidence_level', 'valid_until')
    search_fields = ('assessment_id', 'title', 'target__name')
    raw_id_fields = ('target', 'analyst')
    
    fieldsets = (
        ('Assessment Information', {
            'fields': ('assessment_id', 'title', 'assessment_type', 'target')
        }),
        ('Analysis', {
            'fields': ('analyst', 'threat_level', 'confidence_level', 'valid_until')
        }),
        ('Risk Calculation', {
            'fields': ('probability_score', 'impact_score', 'risk_score'),
            'description': 'Risk score is automatically calculated as (Probability × Impact) ÷ 10'
        }),
        ('Detailed Assessment', {
            'fields': ('key_indicators', 'threat_vectors', 'vulnerabilities', 
                      'mitigation_recommendations')
        })
    )
    
    readonly_fields = ('risk_score',)
    
    def threat_level_badge(self, obj):
        colors = {
            'LOW': 'green',
            'MEDIUM': 'blue', 
            'HIGH': 'orange',
            'CRITICAL': 'red'
        }
        color = colors.get(obj.threat_level, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            color, obj.threat_level
        )
    
    def risk_score_display(self, obj):
        if obj.risk_score >= 70:
            color = 'red'
        elif obj.risk_score >= 50:
            color = 'orange'
        elif obj.risk_score >= 30:
            color = 'blue'
        else:
            color = 'green'
        
        return format_html(
            '<span style="color: {}; font-weight: bold;">{:.1f}</span>',
            color, obj.risk_score
        )
    
    threat_level_badge.short_description = 'Threat Level'
    risk_score_display.short_description = 'Risk Score'


@admin.register(Equipment)
class EquipmentAdmin(SecureModelAdmin):
    list_display = ('equipment_id', 'name', 'equipment_type', 'status_badge',
                   'assigned_to', 'current_location', 'maintenance_status')
    list_filter = ('equipment_type', 'status', 'acquisition_date', 'last_maintenance')
    search_fields = ('equipment_id', 'name', 'model', 'serial_number')
    raw_id_fields = ('assigned_to',)
    
    fieldsets = (
        ('Equipment Information', {
            'fields': ('equipment_id', 'name', 'equipment_type', 'model', 'serial_number')
        }),
        ('Status', {
            'fields': ('status', 'current_location', 'assigned_to')
        }),
        ('Dates', {
            'fields': ('acquisition_date', 'last_maintenance', 'next_maintenance')
        }),
        ('Specifications', {
            'fields': ('specifications', 'notes'),
            'classes': ('collapse',)
        })
    )
    
    def status_badge(self, obj):
        colors = {
            'AVAILABLE': 'green',
            'IN_USE': 'blue',
            'MAINTENANCE': 'orange',
            'DAMAGED': 'red',
            'RETIRED': 'gray'
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            color, obj.get_status_display()
        )
    
    def maintenance_status(self, obj):
        if obj.next_maintenance:
            days_until = (obj.next_maintenance - timezone.now().date()).days
            if days_until < 0:
                return format_html('<span style="color: red;">Overdue by {} days</span>', abs(days_until))
            elif days_until < 30:
                return format_html('<span style="color: orange;">Due in {} days</span>', days_until)
            else:
                return format_html('<span style="color: green;">Scheduled</span>')
        return 'Not scheduled'
    
    status_badge.short_description = 'Status'
    maintenance_status.short_description = 'Maintenance'


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'user', 'action', 'resource_type', 'resource_id',
                   'classification_badge', 'ip_address')
    list_filter = ('action', 'resource_type', 'classification_level', 'timestamp')
    search_fields = ('user__username', 'resource_type', 'resource_id', 'description')
    readonly_fields = ('user', 'action', 'resource_type', 'resource_id', 'description',
                      'ip_address', 'user_agent', 'timestamp', 'classification_level')
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Action Information', {
            'fields': ('user', 'action', 'resource_type', 'resource_id', 'timestamp')
        }),
        ('Details', {
            'fields': ('description', 'classification_level')
        }),
        ('System Information', {
            'fields': ('ip_address', 'user_agent'),
            'classes': ('collapse',)
        })
    )
    
    def has_add_permission(self, request):
        return False  # Audit logs should not be manually created
    
    def has_change_permission(self, request, obj=None):
        return False  # Audit logs should not be modified
    
    def has_delete_permission(self, request, obj=None):
        return False  # Audit logs should not be deleted
    
    def classification_badge(self, obj):
        if obj.classification_level:
            colors = {'U': 'green', 'C': 'blue', 'S': 'orange', 'TS': 'red'}
            color = colors.get(obj.classification_level, 'gray')
            return format_html(
                '<span style="background-color: {}; color: white; padding: 2px 6px; '
                'border-radius: 3px; font-weight: bold;">{}</span>',
                color, obj.classification_level
            )
        return '-'
    
    classification_badge.short_description = 'Classification'


# Custom Admin Site Configuration
admin.site.site_header = "National Intelligence System Administration"
admin.site.site_title = "NIS Admin"
admin.site.index_title = "Intelligence System Management"

# Add custom CSS
class MediaMixin:
    class Media:
        css = {
            'all': ('admin/css/custom_admin.css',)
        }
        js = ('admin/js/custom_admin.js',)

# Apply media to all admin classes
for model_admin in [IntelligenceUserAdmin, DepartmentAdmin, SourceAdmin, 
                   IntelligenceReportAdmin, TargetAdmin, OperationAdmin,
                   IncidentAdmin, SecureMessageAdmin, CollectionRequirementAdmin,
                   ThreatAssessmentAdmin, EquipmentAdmin, AuditLogAdmin]:
    if hasattr(model_admin, 'Media'):
        model_admin.Media.css = getattr(model_admin.Media, 'css', {})
        model_admin.Media.css.setdefault('all', []).append('admin/css/custom_admin.css')
    else:
        model_admin.Media = type('Media', (), {
            'css': {'all': ['admin/css/custom_admin.css']},
            'js': ['admin/js/custom_admin.js']
        })