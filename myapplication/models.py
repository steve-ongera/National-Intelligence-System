from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.utils import timezone
import uuid

# Custom User Model for Intelligence Personnel
class IntelligenceUser(AbstractUser):
    CLEARANCE_LEVELS = [
        ('UNCLASSIFIED', 'Unclassified'),
        ('CONFIDENTIAL', 'Confidential'),
        ('SECRET', 'Secret'),
        ('TOP_SECRET', 'Top Secret'),
        ('TS_SCI', 'Top Secret/SCI'),
    ]
    
    ROLES = [
        ('ANALYST', 'Intelligence Analyst'),
        ('OPERATOR', 'Field Operator'),
        ('SUPERVISOR', 'Supervisor'),
        ('ADMIN', 'System Administrator'),
        ('DIRECTOR', 'Director'),
    ]
    
    employee_id = models.CharField(max_length=20, unique=True)
    clearance_level = models.CharField(max_length=20, choices=CLEARANCE_LEVELS)
    role = models.CharField(max_length=20, choices=ROLES)
    department = models.ForeignKey('Department', on_delete=models.CASCADE, null=True)
    phone = models.CharField(max_length=15, blank=True)
    emergency_contact = models.CharField(max_length=100, blank=True)
    is_active_duty = models.BooleanField(default=True)
    security_clearance_expiry = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.username} - {self.get_role_display()}"

# Organizational Structure
class Department(models.Model):
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=10, unique=True)
    description = models.TextField()
    head = models.ForeignKey(IntelligenceUser, on_delete=models.SET_NULL, null=True, related_name='headed_departments')
    parent_department = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.code} - {self.name}"

# Intelligence Sources and Assets
class Source(models.Model):
    SOURCE_TYPES = [
        ('HUMINT', 'Human Intelligence'),
        ('SIGINT', 'Signals Intelligence'),
        ('GEOINT', 'Geospatial Intelligence'),
        ('OSINT', 'Open Source Intelligence'),
        ('TECHINT', 'Technical Intelligence'),
        ('FININT', 'Financial Intelligence'),
    ]
    
    RELIABILITY_LEVELS = [
        ('A', 'Completely Reliable'),
        ('B', 'Usually Reliable'),
        ('C', 'Fairly Reliable'),
        ('D', 'Not Usually Reliable'),
        ('E', 'Unreliable'),
        ('F', 'Reliability Cannot Be Judged'),
    ]
    
    source_id = models.CharField(max_length=50, unique=True)
    codename = models.CharField(max_length=100)
    source_type = models.CharField(max_length=20, choices=SOURCE_TYPES)
    reliability_level = models.CharField(max_length=1, choices=RELIABILITY_LEVELS)
    handler = models.ForeignKey(IntelligenceUser, on_delete=models.CASCADE, related_name='handled_sources')
    location = models.CharField(max_length=200)
    contact_method = models.TextField()
    is_active = models.BooleanField(default=True)
    recruitment_date = models.DateField()
    last_contact = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'intelligence_source'

    def __str__(self):
        return f"{self.codename} ({self.source_type})"

# Intelligence Reports and Information
class IntelligenceReport(models.Model):
    CLASSIFICATION_LEVELS = [
        ('U', 'Unclassified'),
        ('C', 'Confidential'),
        ('S', 'Secret'),
        ('TS', 'Top Secret'),
    ]
    
    REPORT_TYPES = [
        ('SITREP', 'Situation Report'),
        ('INTREP', 'Intelligence Report'),
        ('SPOTREP', 'Spot Report'),
        ('ASSESSMENT', 'Intelligence Assessment'),
        ('BRIEFING', 'Intelligence Briefing'),
        ('WARNING', 'Intelligence Warning'),
    ]
    
    STATUS_CHOICES = [
        ('DRAFT', 'Draft'),
        ('UNDER_REVIEW', 'Under Review'),
        ('APPROVED', 'Approved'),
        ('DISSEMINATED', 'Disseminated'),
        ('ARCHIVED', 'Archived'),
    ]
    
    report_id = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=200)
    report_type = models.CharField(max_length=20, choices=REPORT_TYPES)
    classification = models.CharField(max_length=2, choices=CLASSIFICATION_LEVELS)
    author = models.ForeignKey(IntelligenceUser, on_delete=models.CASCADE, related_name='authored_reports')
    reviewer = models.ForeignKey(IntelligenceUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_reports')
    source = models.ForeignKey(Source, on_delete=models.CASCADE, null=True, blank=True)
    content = models.TextField()
    executive_summary = models.TextField()
    key_findings = models.TextField()
    recommendations = models.TextField(blank=True)
    confidence_level = models.IntegerField(choices=[(i, f"{i}%") for i in range(10, 101, 10)])
    geographic_focus = models.CharField(max_length=100)
    tags = models.TextField(help_text="Comma-separated tags")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='DRAFT')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    dissemination_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.report_id} - {self.title}"

# Targets and Subjects of Interest
class Target(models.Model):
    TARGET_TYPES = [
        ('PERSON', 'Individual Person'),
        ('ORGANIZATION', 'Organization'),
        ('FACILITY', 'Facility/Location'),
        ('EVENT', 'Event'),
        ('TECHNOLOGY', 'Technology'),
        ('NETWORK', 'Network'),
    ]
    
    THREAT_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    target_id = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=200)
    alias = models.TextField(blank=True, help_text="Known aliases, comma-separated")
    target_type = models.CharField(max_length=20, choices=TARGET_TYPES)
    threat_level = models.CharField(max_length=10, choices=THREAT_LEVELS)
    description = models.TextField()
    location = models.CharField(max_length=200, blank=True)
    nationality = models.CharField(max_length=100, blank=True)
    affiliations = models.TextField(blank=True)
    key_attributes = models.JSONField(default=dict, blank=True)
    is_active = models.BooleanField(default=True)
    priority_score = models.IntegerField(default=1, help_text="1-10 priority scale")
    assigned_analyst = models.ForeignKey(IntelligenceUser, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.target_type})"

# Operations and Missions
class Operation(models.Model):
    OPERATION_TYPES = [
        ('COLLECTION', 'Intelligence Collection'),
        ('SURVEILLANCE', 'Surveillance'),
        ('COUNTERINTEL', 'Counterintelligence'),
        ('COVERT', 'Covert Operation'),
        ('ANALYSIS', 'Analysis Operation'),
        ('SUPPORT', 'Support Operation'),
    ]
    
    STATUS_CHOICES = [
        ('PLANNING', 'Planning'),
        ('APPROVED', 'Approved'),
        ('ACTIVE', 'Active'),
        ('SUSPENDED', 'Suspended'),
        ('COMPLETED', 'Completed'),
        ('ABORTED', 'Aborted'),
    ]
    
    operation_id = models.CharField(max_length=50, unique=True)
    codename = models.CharField(max_length=100)
    operation_type = models.CharField(max_length=20, choices=OPERATION_TYPES)
    classification = models.CharField(max_length=2, choices=IntelligenceReport.CLASSIFICATION_LEVELS)
    commanding_officer = models.ForeignKey(IntelligenceUser, on_delete=models.CASCADE, related_name='commanded_operations')
    objectives = models.TextField()
    description = models.TextField()
    start_date = models.DateTimeField()
    end_date = models.DateTimeField(null=True, blank=True)
    location = models.CharField(max_length=200)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PLANNING')
    budget = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    risk_assessment = models.TextField()
    success_criteria = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.codename} ({self.operation_type})"

# Operation Personnel Assignment
class OperationAssignment(models.Model):
    ASSIGNMENT_ROLES = [
        ('LEAD', 'Team Lead'),
        ('ANALYST', 'Analyst'),
        ('OPERATOR', 'Field Operator'),
        ('SUPPORT', 'Support Personnel'),
        ('SPECIALIST', 'Specialist'),
    ]
    
    operation = models.ForeignKey(Operation, on_delete=models.CASCADE, related_name='assignments')
    personnel = models.ForeignKey(IntelligenceUser, on_delete=models.CASCADE, related_name='operation_assignments')
    role = models.CharField(max_length=20, choices=ASSIGNMENT_ROLES)
    assigned_date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ['operation', 'personnel', 'role']

# Incidents and Events
class Incident(models.Model):
    INCIDENT_TYPES = [
        ('SECURITY_BREACH', 'Security Breach'),
        ('THREAT_DETECTED', 'Threat Detected'),
        ('ASSET_COMPROMISED', 'Asset Compromised'),
        ('OPERATIONAL_FAILURE', 'Operational Failure'),
        ('INTELLIGENCE_LEAK', 'Intelligence Leak'),
        ('COUNTERINTEL_ACTIVITY', 'Counterintelligence Activity'),
    ]
    
    SEVERITY_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    incident_id = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=200)
    incident_type = models.CharField(max_length=30, choices=INCIDENT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS)
    description = models.TextField()
    location = models.CharField(max_length=200)
    date_occurred = models.DateTimeField()
    reported_by = models.ForeignKey(IntelligenceUser, on_delete=models.CASCADE, related_name='reported_incidents')
    investigating_officer = models.ForeignKey(IntelligenceUser, on_delete=models.SET_NULL, null=True, related_name='investigated_incidents')
    related_operation = models.ForeignKey(Operation, on_delete=models.SET_NULL, null=True, blank=True)
    related_targets = models.ManyToManyField(Target, blank=True)
    impact_assessment = models.TextField()
    response_actions = models.TextField()
    lessons_learned = models.TextField(blank=True)
    is_resolved = models.BooleanField(default=False)
    resolution_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.incident_id} - {self.title}"

# Communication and Messages
class SecureMessage(models.Model):
    PRIORITY_LEVELS = [
        ('ROUTINE', 'Routine'),
        ('PRIORITY', 'Priority'),
        ('IMMEDIATE', 'Immediate'),
        ('FLASH', 'Flash'),
    ]
    
    message_id = models.UUIDField(default=uuid.uuid4, unique=True)
    sender = models.ForeignKey(IntelligenceUser, on_delete=models.CASCADE, related_name='sent_messages')
    recipients = models.ManyToManyField(IntelligenceUser, related_name='received_messages')
    subject = models.CharField(max_length=200)
    content = models.TextField()
    classification = models.CharField(max_length=2, choices=IntelligenceReport.CLASSIFICATION_LEVELS)
    priority = models.CharField(max_length=15, choices=PRIORITY_LEVELS, default='ROUTINE')
    is_encrypted = models.BooleanField(default=True)
    read_receipt_required = models.BooleanField(default=False)
    sent_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-sent_at']

    def __str__(self):
        return f"{self.subject} - {self.sender.username}"

# Message Read Status
class MessageReadStatus(models.Model):
    message = models.ForeignKey(SecureMessage, on_delete=models.CASCADE, related_name='read_statuses')
    recipient = models.ForeignKey(IntelligenceUser, on_delete=models.CASCADE)
    read_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['message', 'recipient']

# Intelligence Collection Requirements
class CollectionRequirement(models.Model):
    REQUIREMENT_TYPES = [
        ('PIR', 'Priority Intelligence Requirement'),
        ('SIR', 'Specific Information Requirement'),
        ('EEI', 'Essential Elements of Information'),
        ('RFI', 'Request for Information'),
    ]
    
    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('SATISFIED', 'Satisfied'),
        ('SUPERSEDED', 'Superseded'),
        ('CANCELLED', 'Cancelled'),
    ]
    
    requirement_id = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=200)
    requirement_type = models.CharField(max_length=10, choices=REQUIREMENT_TYPES)
    description = models.TextField()
    justification = models.TextField()
    requestor = models.ForeignKey(IntelligenceUser, on_delete=models.CASCADE, related_name='requested_requirements')
    assigned_collector = models.ForeignKey(IntelligenceUser, on_delete=models.SET_NULL, null=True, related_name='assigned_requirements')
    target = models.ForeignKey(Target, on_delete=models.CASCADE, null=True, blank=True)
    priority_level = models.IntegerField(choices=[(i, f"Priority {i}") for i in range(1, 6)])
    due_date = models.DateTimeField()
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='ACTIVE')
    geographic_focus = models.CharField(max_length=100)
    collection_methods = models.TextField(help_text="Suggested collection methods")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    satisfied_date = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.requirement_id} - {self.title}"

# Analysis and Assessments
class ThreatAssessment(models.Model):
    ASSESSMENT_TYPES = [
        ('STRATEGIC', 'Strategic Assessment'),
        ('TACTICAL', 'Tactical Assessment'),
        ('OPERATIONAL', 'Operational Assessment'),
        ('TECHNICAL', 'Technical Assessment'),
    ]
    
    assessment_id = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=200)
    assessment_type = models.CharField(max_length=20, choices=ASSESSMENT_TYPES)
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    analyst = models.ForeignKey(IntelligenceUser, on_delete=models.CASCADE, related_name='threat_assessments')
    threat_level = models.CharField(max_length=10, choices=Target.THREAT_LEVELS)
    probability_score = models.IntegerField(help_text="Probability percentage 1-100")
    impact_score = models.IntegerField(help_text="Impact score 1-10")
    risk_score = models.FloatField(editable=False)  # Calculated field
    key_indicators = models.TextField()
    threat_vectors = models.TextField()
    vulnerabilities = models.TextField()
    mitigation_recommendations = models.TextField()
    confidence_level = models.IntegerField(choices=[(i, f"{i}%") for i in range(10, 101, 10)])
    valid_until = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        # Calculate risk score (probability * impact / 10)
        self.risk_score = (self.probability_score * self.impact_score) / 10
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.assessment_id} - {self.title}"

# Equipment and Resources
class Equipment(models.Model):
    EQUIPMENT_TYPES = [
        ('SURVEILLANCE', 'Surveillance Equipment'),
        ('COMMUNICATIONS', 'Communications Equipment'),
        ('COMPUTING', 'Computing Equipment'),
        ('VEHICLE', 'Vehicle'),
        ('WEAPONS', 'Weapons'),
        ('TECHNICAL', 'Technical Equipment'),
    ]
    
    STATUS_CHOICES = [
        ('AVAILABLE', 'Available'),
        ('IN_USE', 'In Use'),
        ('MAINTENANCE', 'Under Maintenance'),
        ('DAMAGED', 'Damaged'),
        ('RETIRED', 'Retired'),
    ]
    
    equipment_id = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=100)
    equipment_type = models.CharField(max_length=20, choices=EQUIPMENT_TYPES)
    model = models.CharField(max_length=100)
    serial_number = models.CharField(max_length=100, unique=True)
    acquisition_date = models.DateField()
    current_location = models.CharField(max_length=200)
    assigned_to = models.ForeignKey(IntelligenceUser, on_delete=models.SET_NULL, null=True, blank=True)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='AVAILABLE')
    last_maintenance = models.DateField(null=True, blank=True)
    next_maintenance = models.DateField(null=True, blank=True)
    specifications = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.equipment_id} - {self.name}"

# Audit Trail for Security
class AuditLog(models.Model):
    ACTION_TYPES = [
        ('CREATE', 'Create'),
        ('READ', 'Read'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('ACCESS_DENIED', 'Access Denied'),
        ('EXPORT', 'Export Data'),
        ('PRINT', 'Print Document'),
    ]
    
    user = models.ForeignKey(IntelligenceUser, on_delete=models.CASCADE)
    action = models.CharField(max_length=20, choices=ACTION_TYPES)
    resource_type = models.CharField(max_length=50)  # Model name
    resource_id = models.CharField(max_length=50, blank=True)  # Object ID
    description = models.TextField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    classification_level = models.CharField(max_length=2, choices=IntelligenceReport.CLASSIFICATION_LEVELS, blank=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['resource_type', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.timestamp}"