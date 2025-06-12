# National Intelligence System (NIS)

A comprehensive Django-based intelligence management platform designed for national security agencies to handle intelligence operations, personnel management, threat assessment, and secure communications.

## 🏛️ System Overview

The National Intelligence System provides a centralized platform for:
- **Personnel Management**: Role-based access with security clearance levels
- **Intelligence Operations**: Mission planning, execution, and monitoring
- **Source Management**: HUMINT, SIGINT, GEOINT, and other intelligence sources
- **Threat Assessment**: Risk analysis and threat level calculations
- **Secure Communications**: Encrypted messaging with classification levels
- **Audit & Compliance**: Complete activity logging and security monitoring

## 🏗️ System Architecture

### Core Modules

```
NIS/
├── Users & Security
│   ├── IntelligenceUser (Personnel)
│   ├── Department (Organization)
│   └── AuditLog (Security Monitoring)
├── Intelligence Operations
│   ├── Operation (Missions)
│   ├── OperationAssignment (Personnel Assignment)
│   └── IntelligenceReport (Reporting)
├── Sources & Targets
│   ├── Source (Intelligence Assets)
│   ├── Target (Subjects of Interest)
│   └── ThreatAssessment (Risk Analysis)
├── Collection & Analysis
│   ├── CollectionRequirement (Tasking)
│   └── Incident (Event Management)
├── Communications
│   ├── SecureMessage (Internal Comms)
│   └── MessageReadStatus (Delivery Tracking)
└── Resources
    └── Equipment (Asset Management)
```

## 🚀 Installation & Setup

### Prerequisites
- Python 3.9+
- Django 4.2+
- PostgreSQL 12+ (recommended for production)
- Redis (for caching and sessions)

### Installation Steps

1. **Clone the Repository**
```bash
git clone https://github.com/your-org/national-intelligence-system.git
cd national-intelligence-system
```

2. **Create Virtual Environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

4. **Database Setup**
```bash
# Create PostgreSQL database
createdb intelligence_system

# Run migrations
python manage.py makemigrations
python manage.py migrate
```

5. **Create Superuser**
```bash
python manage.py createsuperuser
```

6. **Load Initial Data**
```bash
python manage.py loaddata fixtures/initial_departments.json
python manage.py loaddata fixtures/sample_users.json
```

## 👥 User Roles & Permissions

### Security Clearance Levels
- **UNCLASSIFIED**: Basic access to non-sensitive information
- **CONFIDENTIAL**: Access to information that could damage national security
- **SECRET**: Access to information that could cause serious damage
- **TOP_SECRET**: Access to information that could cause exceptionally grave damage
- **TS_SCI**: Top Secret with Sensitive Compartmented Information access

### User Roles
- **ANALYST**: Intelligence analysis and report generation
- **OPERATOR**: Field operations and source management
- **SUPERVISOR**: Team management and operation oversight
- **ADMIN**: System administration and user management
- **DIRECTOR**: Executive oversight and strategic decision-making

## 📋 System Usage Guide

### 1. Personnel Management

#### Creating Intelligence Personnel
```python
from myapp.models import IntelligenceUser, Department

# Create new analyst
analyst = IntelligenceUser.objects.create_user(
    username='j.smith',
    email='j.smith@agency.gov',
    first_name='John',
    last_name='Smith',
    employee_id='EMP001',
    clearance_level='SECRET',
    role='ANALYST',
    department=Department.objects.get(code='INTEL')
)
```

#### Managing Departments
```python
# Create department hierarchy
parent_dept = Department.objects.create(
    name='Intelligence Division',
    code='INTEL',
    description='Primary intelligence analysis division'
)

sub_dept = Department.objects.create(
    name='Counter-Terrorism Unit',
    code='CTU',
    description='Counter-terrorism analysis and operations',
    parent_department=parent_dept
)
```

### 2. Source Management

#### Registering Intelligence Sources
```python
from myapp.models import Source, IntelligenceUser

# Register HUMINT source
source = Source.objects.create(
    source_id='HUMINT-001',
    codename='BLACKBIRD',
    source_type='HUMINT',
    reliability_level='B',  # Usually Reliable
    handler=IntelligenceUser.objects.get(username='field.agent'),
    location='Eastern Europe',
    contact_method='Encrypted messaging via Signal',
    recruitment_date='2024-01-15'
)
```

#### Source Types and Reliability
- **HUMINT**: Human Intelligence sources
- **SIGINT**: Signals Intelligence collection
- **GEOINT**: Geospatial Intelligence sources
- **OSINT**: Open Source Intelligence
- **TECHINT**: Technical Intelligence
- **FININT**: Financial Intelligence

### 3. Intelligence Reporting

#### Creating Intelligence Reports
```python
from myapp.models import IntelligenceReport

report = IntelligenceReport.objects.create(
    report_id='INTREP-2024-001',
    title='Threat Assessment: Regional Instability',
    report_type='ASSESSMENT',
    classification='S',  # Secret
    author=IntelligenceUser.objects.get(username='analyst1'),
    source=Source.objects.get(codename='BLACKBIRD'),
    content='Detailed intelligence analysis...',
    executive_summary='Key findings summary...',
    key_findings='Critical intelligence points...',
    confidence_level=80,
    geographic_focus='Middle East',
    tags='terrorism, regional-security, threat-assessment'
)
```

#### Report Workflow
1. **DRAFT**: Initial report creation by analyst
2. **UNDER_REVIEW**: Submitted for supervisor review
3. **APPROVED**: Approved by supervisor
4. **DISSEMINATED**: Distributed to authorized personnel
5. **ARCHIVED**: Long-term storage

### 4. Operations Management

#### Planning Operations
```python
from myapp.models import Operation, OperationAssignment

# Create new operation
operation = Operation.objects.create(
    operation_id='OP-SAFEGUARD-2024',
    codename='OPERATION SAFEGUARD',
    operation_type='SURVEILLANCE',
    classification='TS',
    commanding_officer=IntelligenceUser.objects.get(username='team.lead'),
    objectives='Monitor suspect activities in target area',
    description='Long-term surveillance operation...',
    start_date='2024-06-01T00:00:00Z',
    location='Urban Environment - Grid 123',
    risk_assessment='Medium risk operation with standard protocols',
    success_criteria='Successful intelligence collection without compromise'
)

# Assign personnel
OperationAssignment.objects.create(
    operation=operation,
    personnel=IntelligenceUser.objects.get(username='field.operator1'),
    role='LEAD'
)
```

### 5. Target Management

#### Creating Target Profiles
```python
from myapp.models import Target

target = Target.objects.create(
    target_id='TGT-001',
    name='Subject Alpha',
    alias='Known alias 1, Known alias 2',
    target_type='PERSON',
    threat_level='HIGH',
    description='High-value target involved in...',
    location='Unknown - Last seen in...',
    nationality='Unknown',
    key_attributes={
        'height': '6ft 2in',
        'distinguishing_marks': 'Scar on left cheek',
        'languages': ['English', 'Arabic', 'Russian']
    },
    priority_score=9,
    assigned_analyst=IntelligenceUser.objects.get(username='analyst2')
)
```

### 6. Threat Assessment

#### Conducting Risk Analysis
```python
from myapp.models import ThreatAssessment

assessment = ThreatAssessment.objects.create(
    assessment_id='THREAT-2024-001',
    title='Regional Security Threat Analysis',
    assessment_type='STRATEGIC',
    target=Target.objects.get(target_id='TGT-001'),
    analyst=IntelligenceUser.objects.get(username='threat.analyst'),
    threat_level='HIGH',
    probability_score=75,  # 75% probability
    impact_score=8,        # High impact (1-10 scale)
    # risk_score automatically calculated: (75 * 8) / 10 = 60
    key_indicators='Increased communications, movement patterns...',
    threat_vectors='Cyber attack, physical infiltration...',
    vulnerabilities='Network security gaps, personnel access...',
    mitigation_recommendations='Enhanced monitoring, access restrictions...',
    confidence_level=80,
    valid_until='2024-12-31T23:59:59Z'
)
```

### 7. Secure Communications

#### Sending Classified Messages
```python
from myapp.models import SecureMessage

message = SecureMessage.objects.create(
    sender=IntelligenceUser.objects.get(username='sender'),
    subject='Operation Status Update',
    content='Classified operation update content...',
    classification='S',  # Secret
    priority='IMMEDIATE',
    read_receipt_required=True,
    expires_at='2024-07-01T23:59:59Z'
)

# Add recipients
message.recipients.add(
    IntelligenceUser.objects.get(username='recipient1'),
    IntelligenceUser.objects.get(username='recipient2')
)
```

### 8. Collection Requirements

#### Tasking Intelligence Collection
```python
from myapp.models import CollectionRequirement

requirement = CollectionRequirement.objects.create(
    requirement_id='PIR-2024-001',
    title='Economic Intelligence on Target Region',
    requirement_type='PIR',  # Priority Intelligence Requirement
    description='Collect economic intelligence on regional markets...',
    justification='Critical for strategic planning...',
    requestor=IntelligenceUser.objects.get(username='strategist'),
    assigned_collector=IntelligenceUser.objects.get(username='collector'),
    target=Target.objects.get(target_id='TGT-REGION-001'),
    priority_level=1,  # Highest priority
    due_date='2024-08-01T00:00:00Z',
    geographic_focus='Southeast Asia',
    collection_methods='OSINT, HUMINT, Financial analysis'
)
```

### 9. Incident Management

#### Reporting Security Incidents
```python
from myapp.models import Incident

incident = Incident.objects.create(
    incident_id='INC-2024-001',
    title='Potential Source Compromise',
    incident_type='ASSET_COMPROMISED',
    severity='HIGH',
    description='Source BLACKBIRD may have been compromised...',
    location='Eastern Europe - Safe House Alpha',
    date_occurred='2024-06-10T14:30:00Z',
    reported_by=IntelligenceUser.objects.get(username='field.supervisor'),
    investigating_officer=IntelligenceUser.objects.get(username='security.investigator'),
    impact_assessment='Potential intelligence loss, source safety at risk',
    response_actions='Source extraction initiated, safe house abandoned'
)
```

## 🔐 Security Features

### Classification System
All sensitive data is classified according to standard levels:
- Documents auto-classify based on content and source
- Access control enforced at database and application levels
- Audit trails for all classified data access

### Audit Logging
```python
# Automatic audit logging for all actions
from myapp.models import AuditLog

# Logs are automatically created for:
# - User logins/logouts
# - Data access and modifications
# - Report generation and distribution
# - System administration actions
```

### Access Control
- Role-based permissions
- Clearance-level restrictions
- Need-to-know basis enforcement
- Session management with timeout

## 📊 Reporting & Analytics

### Built-in Reports
- **Intelligence Summary Reports**: Executive briefings
- **Operational Status Reports**: Mission progress tracking
- **Threat Assessment Reports**: Risk analysis summaries
- **Source Performance Reports**: Asset effectiveness metrics
- **Security Audit Reports**: Compliance monitoring

### Custom Queries
```python
# Example analytics queries
from django.db.models import Count, Q
from myapp.models import *

# Active high-priority targets by region
high_priority_targets = Target.objects.filter(
    threat_level='HIGH',
    is_active=True
).values('location').annotate(
    count=Count('id')
).order_by('-count')

# Recent intelligence reports by classification
recent_reports = IntelligenceReport.objects.filter(
    created_at__gte=timezone.now() - timedelta(days=30)
).values('classification').annotate(
    count=Count('id')
)
```

## 🛠️ API Usage

### RESTful API Endpoints
```bash
# Authentication
POST /api/auth/login/
POST /api/auth/logout/

# Intelligence Reports
GET  /api/reports/
POST /api/reports/
GET  /api/reports/{id}/
PUT  /api/reports/{id}/

# Operations
GET  /api/operations/
POST /api/operations/
GET  /api/operations/{id}/

# Targets
GET  /api/targets/
POST /api/targets/
GET  /api/targets/{id}/threat-assessments/

# Sources
GET  /api/sources/
POST /api/sources/
PUT  /api/sources/{id}/
```

## 🔧 Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/intelligence_system

# Security
SECRET_KEY=your-secret-key-here
DEBUG=False
ALLOWED_HOSTS=your-domain.com

# Cache
REDIS_URL=redis://localhost:6379/0

# Email
EMAIL_HOST=smtp.agency.gov
EMAIL_PORT=587
EMAIL_USE_TLS=True
```

### Security Settings
```python
# settings.py additions
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'

# Session security
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_AGE = 3600  # 1 hour timeout
```

## 📚 Best Practices

### Data Classification
1. Always classify data at creation
2. Review classification levels regularly
3. Implement need-to-know restrictions
4. Monitor access to classified information

### Operational Security
1. Use secure communication channels
2. Regularly update threat assessments
3. Maintain operational security protocols
4. Conduct regular security audits

### Source Protection
1. Limit handler access to source details
2. Use code names consistently
3. Regular security reviews of source operations
4. Implement source deconfliction procedures

## 🚨 Emergency Procedures

### System Compromise
1. Immediately isolate affected systems
2. Activate incident response team
3. Preserve audit logs
4. Notify security officer
5. Implement containment procedures

### Source Compromise
1. Execute source protection protocols
2. Assess operational impact
3. Implement damage control measures
4. Review operational security

## 📞 Support & Maintenance

### System Administration
- Regular database backups
- Security patch management
- User access reviews
- Performance monitoring

### Help Desk
- Internal support: ext. 2400
- Security issues: ext. 2401
- Technical support: ext. 2402

## 📄 Compliance & Legal

### Records Management
- All intelligence records retained per agency policy
- Automatic archiving after specified periods
- Legal hold capabilities
- FOIA exemption tracking

### Privacy Protection
- Personal data protection measures
- Data minimization principles
- Regular privacy impact assessments
- Cross-border data transfer restrictions

---

**Classification**: UNCLASSIFIED
**Version**: 1.0
**Last Updated**: June 2024
**Next Review**: December 2024

*This system contains sensitive national security information. Access is restricted to authorized personnel with appropriate security clearances. Unauthorized access, use, or disclosure is prohibited and may result in criminal prosecution.*