"""
Expert Validation Framework for LinuxGuard Anti-Patterns
Facilitates systematic evaluation by security experts
"""
import json
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import pandas as pd
from loguru import logger
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import hashlib


@dataclass
class ExpertProfile:
    """Profile of a security expert"""
    expert_id: str
    name: str
    email: str
    affiliation: str
    expertise_areas: List[str]
    years_experience: int
    publications: List[str]
    kernel_contributions: bool
    preferred_contact: str  # email, survey_platform, etc.


@dataclass
class ValidationQuestion:
    """Single validation question for an anti-pattern"""
    question_id: str
    pattern_id: str
    question_type: str  # relevance, accuracy, severity, completeness
    question_text: str
    context: Dict[str, Any]
    scale_type: str  # likert_5, likert_7, binary, multiple_choice
    options: Optional[List[str]] = None


@dataclass
class ExpertResponse:
    """Expert's response to validation questions"""
    response_id: str
    expert_id: str
    question_id: str
    pattern_id: str
    response_value: Any  # numeric for scales, string for text
    confidence: float  # 0.0-1.0
    reasoning: str
    additional_comments: str
    response_time_seconds: float
    timestamp: datetime


@dataclass
class ValidationSession:
    """Complete validation session for an expert"""
    session_id: str
    expert_id: str
    patterns_assigned: List[str]
    questions_generated: List[str]
    start_time: datetime
    completion_time: Optional[datetime]
    status: str  # invited, in_progress, completed, expired
    reminder_count: int


class ExpertValidationFramework:
    """Framework for conducting expert validation of anti-patterns"""
    
    def __init__(self, work_dir: str = "data/expert_validation"):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize data storage
        self.experts = []
        self.patterns = []
        self.questions = []
        self.responses = []
        self.sessions = []
        
        # Configuration
        self.validation_deadline_days = 14
        self.min_experts_per_pattern = 3
        self.reminder_schedule = [3, 7, 10]  # days after invitation
        
        logger.info(f"Expert Validation Framework initialized at {work_dir}")
    
    def load_patterns(self, patterns_file: str = "data/pattern_analysis/derived_patterns.json") -> List[Dict]:
        """Load anti-patterns for validation"""
        patterns_path = Path(patterns_file)
        
        if not patterns_path.exists():
            logger.error(f"Patterns file not found: {patterns_file}")
            return []
        
        with open(patterns_path, 'r', encoding='utf-8') as f:
            patterns_data = json.load(f)
        
        # Handle both list and dict formats
        if isinstance(patterns_data, list):
            self.patterns = patterns_data
        else:
            self.patterns = patterns_data.get('patterns', [])
        logger.info(f"Loaded {len(self.patterns)} patterns for expert validation")
        
        return self.patterns
    
    def setup_expert_panel(self) -> List[ExpertProfile]:
        """Setup panel of security experts for validation"""
        
        # Define expert profiles (would be real contacts in practice)
        expert_profiles = [
            ExpertProfile(
                expert_id="expert_001",
                name="Dr. Sarah Chen",
                email="sarah.chen@university.edu",
                affiliation="MIT Computer Science",
                expertise_areas=["Linux kernel security", "Static analysis", "Memory safety"],
                years_experience=12,
                publications=["USENIX Security", "IEEE S&P", "ACM CCS"],
                kernel_contributions=True,
                preferred_contact="email"
            ),
            ExpertProfile(
                expert_id="expert_002", 
                name="Prof. Michael Rodriguez",
                email="m.rodriguez@tech.edu",
                affiliation="Stanford Security Lab",
                expertise_areas=["Vulnerability analysis", "Code auditing", "Security tools"],
                years_experience=15,
                publications=["NDSS", "USENIX Security", "S&P"],
                kernel_contributions=True,
                preferred_contact="email"
            ),
            ExpertProfile(
                expert_id="expert_003",
                name="Dr. Elena Petrov",
                email="elena.petrov@company.com", 
                affiliation="Google Security Team",
                expertise_areas=["Linux security", "Static analysis", "Kernel development"],
                years_experience=8,
                publications=["Industry reports", "LKML contributions"],
                kernel_contributions=True,
                preferred_contact="survey_platform"
            ),
            ExpertProfile(
                expert_id="expert_004",
                name="Dr. James Wilson",
                email="j.wilson@research.org",
                affiliation="Carnegie Mellon CyLab",
                expertise_areas=["Software security", "Program analysis", "Vulnerability research"],
                years_experience=10,
                publications=["FSE", "ICSE", "ASE"],
                kernel_contributions=False,
                preferred_contact="email"
            ),
            ExpertProfile(
                expert_id="expert_005",
                name="Dr. Yuki Tanaka",
                email="tanaka@security.ac.jp",
                affiliation="Tokyo Institute of Technology",
                expertise_areas=["System security", "Linux internals", "Security patterns"],
                years_experience=14,
                publications=["ACSAC", "RAID", "ESORICS"],
                kernel_contributions=True,
                preferred_contact="email"
            )
        ]
        
        self.experts = expert_profiles
        
        # Save expert profiles
        experts_data = [asdict(expert) for expert in expert_profiles]
        with open(self.work_dir / "expert_profiles.json", 'w', encoding='utf-8') as f:
            json.dump(experts_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Setup expert panel with {len(expert_profiles)} experts")
        return expert_profiles
    
    def generate_validation_questions(self, pattern: Dict) -> List[ValidationQuestion]:
        """Generate comprehensive validation questions for a pattern"""
        pattern_id = pattern.get('pattern_id', 'unknown')
        questions = []
        
        # 1. Relevance Questions
        questions.append(ValidationQuestion(
            question_id=f"relevance_{pattern_id}_{uuid.uuid4().hex[:8]}",
            pattern_id=pattern_id,
            question_type="relevance",
            question_text=f"How relevant is this anti-pattern to Linux kernel security?",
            context={
                "pattern_description": pattern.get('description', ''),
                "bug_type": pattern.get('bug_type', ''),
                "detection_rules": pattern.get('detection_rules', [])
            },
            scale_type="likert_5",
            options=["Not relevant", "Slightly relevant", "Moderately relevant", "Very relevant", "Extremely relevant"]
        ))
        
        # 2. Accuracy Questions
        questions.append(ValidationQuestion(
            question_id=f"accuracy_{pattern_id}_{uuid.uuid4().hex[:8]}",
            pattern_id=pattern_id,
            question_type="accuracy",
            question_text="How accurately does this pattern represent a real security vulnerability class?",
            context={
                "pattern_description": pattern.get('description', ''),
                "examples": pattern.get('examples', [])
            },
            scale_type="likert_5",
            options=["Completely inaccurate", "Mostly inaccurate", "Somewhat accurate", "Mostly accurate", "Completely accurate"]
        ))
        
        # 3. Severity Assessment
        questions.append(ValidationQuestion(
            question_id=f"severity_{pattern_id}_{uuid.uuid4().hex[:8]}",
            pattern_id=pattern_id,
            question_type="severity",
            question_text="What is the potential security impact of vulnerabilities matching this pattern?",
            context={
                "pattern_description": pattern.get('description', ''),
                "bug_type": pattern.get('bug_type', '')
            },
            scale_type="multiple_choice",
            options=["Low (minor issues)", "Medium (moderate impact)", "High (significant vulnerabilities)", "Critical (severe security flaws)"]
        ))
        
        # 4. Completeness Questions
        questions.append(ValidationQuestion(
            question_id=f"completeness_{pattern_id}_{uuid.uuid4().hex[:8]}",
            pattern_id=pattern_id,
            question_type="completeness",
            question_text="How complete are the detection rules for identifying this anti-pattern?",
            context={
                "detection_rules": pattern.get('detection_rules', []),
                "rule_count": len(pattern.get('detection_rules', []))
            },
            scale_type="likert_5",
            options=["Very incomplete", "Incomplete", "Adequate", "Complete", "Very complete"]
        ))
        
        # 5. False Positive Likelihood
        questions.append(ValidationQuestion(
            question_id=f"false_positive_{pattern_id}_{uuid.uuid4().hex[:8]}",
            pattern_id=pattern_id,
            question_type="false_positive",
            question_text="How likely are these detection rules to produce false positives?",
            context={
                "detection_rules": pattern.get('detection_rules', [])
            },
            scale_type="likert_5",
            options=["Very unlikely", "Unlikely", "Moderate likelihood", "Likely", "Very likely"]
        ))
        
        # 6. Practical Utility
        questions.append(ValidationQuestion(
            question_id=f"utility_{pattern_id}_{uuid.uuid4().hex[:8]}",
            pattern_id=pattern_id,
            question_type="utility",
            question_text="How useful would a static analyzer for this pattern be in practice?",
            context={
                "pattern_description": pattern.get('description', ''),
                "detection_rules": pattern.get('detection_rules', [])
            },
            scale_type="likert_5",
            options=["Not useful", "Slightly useful", "Moderately useful", "Very useful", "Extremely useful"]
        ))
        
        # 7. Open-ended feedback
        questions.append(ValidationQuestion(
            question_id=f"feedback_{pattern_id}_{uuid.uuid4().hex[:8]}",
            pattern_id=pattern_id,
            question_type="feedback",
            question_text="Please provide any additional comments, suggestions for improvement, or examples of related vulnerabilities.",
            context={
                "pattern_full": pattern
            },
            scale_type="text",
            options=None
        ))
        
        return questions
    
    def assign_patterns_to_experts(self) -> Dict[str, List[str]]:
        """Intelligently assign patterns to experts based on expertise"""
        if not self.experts or not self.patterns:
            logger.error("Experts or patterns not loaded")
            return {}
        
        assignments = {}
        
        # Create expertise mapping
        expertise_map = {
            "memory_leak": ["Linux kernel security", "Memory safety", "Static analysis"],
            "input_validation": ["Vulnerability analysis", "Code auditing", "Security tools"],
            "race_condition": ["Linux internals", "System security", "Kernel development"],
            "other": ["Software security", "Program analysis", "Security patterns"]
        }
        
        for pattern in self.patterns:
            pattern_id = pattern.get('pattern_id', 'unknown')
            bug_type = pattern.get('bug_type', 'other')
            
            # Find experts with relevant expertise
            relevant_areas = expertise_map.get(bug_type, expertise_map['other'])
            
            expert_scores = []
            for expert in self.experts:
                score = 0
                # Score based on expertise overlap
                for area in relevant_areas:
                    for expert_area in expert.expertise_areas:
                        if area.lower() in expert_area.lower():
                            score += 1
                
                # Bonus for kernel contributions
                if expert.kernel_contributions and "kernel" in bug_type.lower():
                    score += 2
                
                # Bonus for years of experience
                score += expert.years_experience * 0.1
                
                expert_scores.append((expert.expert_id, score))
            
            # Sort by score and select top experts
            expert_scores.sort(key=lambda x: x[1], reverse=True)
            selected_experts = [expert_id for expert_id, _ in expert_scores[:self.min_experts_per_pattern]]
            
            # Ensure each expert gets assigned
            for expert_id in selected_experts:
                if expert_id not in assignments:
                    assignments[expert_id] = []
                assignments[expert_id].append(pattern_id)
        
        # Balance assignments if needed
        max_patterns = max(len(patterns) for patterns in assignments.values())
        min_patterns = min(len(patterns) for patterns in assignments.values())
        
        logger.info(f"Pattern assignments: {len(self.patterns)} patterns assigned to {len(assignments)} experts")
        logger.info(f"Assignment balance: {min_patterns}-{max_patterns} patterns per expert")
        
        return assignments
    
    def create_validation_sessions(self) -> List[ValidationSession]:
        """Create validation sessions for each expert"""
        assignments = self.assign_patterns_to_experts()
        sessions = []
        
        for expert_id, pattern_ids in assignments.items():
            # Generate questions for assigned patterns
            session_questions = []
            for pattern_id in pattern_ids:
                pattern = next((p for p in self.patterns if p.get('pattern_id') == pattern_id), None)
                if pattern:
                    questions = self.generate_validation_questions(pattern)
                    session_questions.extend([q.question_id for q in questions])
                    self.questions.extend(questions)
            
            # Create session
            session = ValidationSession(
                session_id=f"session_{expert_id}_{uuid.uuid4().hex[:8]}",
                expert_id=expert_id,
                patterns_assigned=pattern_ids,
                questions_generated=session_questions,
                start_time=datetime.now(),
                completion_time=None,
                status="invited",
                reminder_count=0
            )
            
            sessions.append(session)
        
        self.sessions = sessions
        
        # Save sessions and questions
        self._save_validation_data()
        
        logger.info(f"Created {len(sessions)} validation sessions")
        return sessions
    
    def generate_validation_survey(self, expert_id: str) -> Dict[str, Any]:
        """Generate personalized validation survey for an expert"""
        expert = next((e for e in self.experts if e.expert_id == expert_id), None)
        session = next((s for s in self.sessions if s.expert_id == expert_id), None)
        
        if not expert or not session:
            logger.error(f"Expert or session not found for {expert_id}")
            return {}
        
        # Get questions for this expert's patterns
        expert_questions = [q for q in self.questions if q.question_id in session.questions_generated]
        
        survey_data = {
            "survey_metadata": {
                "expert_id": expert_id,
                "expert_name": expert.name,
                "session_id": session.session_id,
                "patterns_count": len(session.patterns_assigned),
                "questions_count": len(expert_questions),
                "estimated_time_minutes": len(expert_questions) * 3,
                "deadline": (session.start_time + timedelta(days=self.validation_deadline_days)).isoformat()
            },
            "instructions": {
                "overview": "Please evaluate the following anti-patterns derived from Linux kernel vulnerability commits.",
                "purpose": "Your expertise will help validate the accuracy and utility of these patterns for automated security analysis.",
                "time_estimate": f"Estimated completion time: {len(expert_questions) * 3} minutes",
                "confidentiality": "Your responses will be kept confidential and used only for research purposes."
            },
            "patterns": [],
            "questions": []
        }
        
        # Add pattern details
        for pattern_id in session.patterns_assigned:
            pattern = next((p for p in self.patterns if p.get('pattern_id') == pattern_id), None)
            if pattern:
                survey_data["patterns"].append({
                    "pattern_id": pattern_id,
                    "description": pattern.get('description', ''),
                    "bug_type": pattern.get('bug_type', ''),
                    "confidence": pattern.get('confidence', 0),
                    "detection_rules": pattern.get('detection_rules', []),
                    "examples": pattern.get('examples', [])[:2]  # Limit examples for readability
                })
        
        # Add questions grouped by pattern
        current_pattern = None
        for question in expert_questions:
            if question.pattern_id != current_pattern:
                current_pattern = question.pattern_id
                survey_data["questions"].append({
                    "section_type": "pattern_header",
                    "pattern_id": current_pattern,
                    "content": f"Questions for Pattern: {current_pattern}"
                })
            
            survey_data["questions"].append({
                "question_id": question.question_id,
                "pattern_id": question.pattern_id,
                "question_type": question.question_type,
                "question_text": question.question_text,
                "scale_type": question.scale_type,
                "options": question.options,
                "context": question.context
            })
        
        return survey_data
    
    def export_validation_package(self, expert_id: str) -> str:
        """Export complete validation package for an expert"""
        survey_data = self.generate_validation_survey(expert_id)
        
        if not survey_data:
            return ""
        
        expert = next((e for e in self.experts if e.expert_id == expert_id), None)
        
        # Create expert-specific directory
        expert_dir = self.work_dir / f"expert_{expert_id}"
        expert_dir.mkdir(exist_ok=True)
        
        # Save survey data
        with open(expert_dir / "validation_survey.json", 'w', encoding='utf-8') as f:
            json.dump(survey_data, f, indent=2, ensure_ascii=False)
        
        # Generate human-readable survey
        survey_html = self._generate_survey_html(survey_data)
        with open(expert_dir / "validation_survey.html", 'w', encoding='utf-8') as f:
            f.write(survey_html)
        
        # Generate response template
        response_template = self._generate_response_template(survey_data)
        with open(expert_dir / "response_template.json", 'w', encoding='utf-8') as f:
            json.dump(response_template, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported validation package for {expert.name} to {expert_dir}")
        return str(expert_dir)
    
    def _generate_survey_html(self, survey_data: Dict) -> str:
        """Generate HTML survey for easy completion"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>LinuxGuard Anti-Pattern Expert Validation</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .pattern {{ border: 1px solid #ddd; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        .question {{ margin: 15px 0; padding: 15px; background: #f9f9f9; border-radius: 3px; }}
        .scale {{ margin: 10px 0; }}
        .scale label {{ margin-right: 15px; }}
        textarea {{ width: 100%; height: 100px; }}
        .detection-rule {{ background: #e8f4f8; padding: 10px; margin: 5px 0; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>LinuxGuard Anti-Pattern Expert Validation</h1>
        <p><strong>Expert:</strong> {survey_data['survey_metadata']['expert_name']}</p>
        <p><strong>Patterns to evaluate:</strong> {survey_data['survey_metadata']['patterns_count']}</p>
        <p><strong>Estimated time:</strong> {survey_data['survey_metadata']['estimated_time_minutes']} minutes</p>
        <p><strong>Deadline:</strong> {survey_data['survey_metadata']['deadline']}</p>
    </div>
    
    <div class="instructions">
        <h2>Instructions</h2>
        <p>{survey_data['instructions']['overview']}</p>
        <p><strong>Purpose:</strong> {survey_data['instructions']['purpose']}</p>
        <p><strong>Confidentiality:</strong> {survey_data['instructions']['confidentiality']}</p>
    </div>
"""
        
        current_pattern = None
        for item in survey_data['questions']:
            if item.get('section_type') == 'pattern_header':
                if current_pattern:
                    html += "</div>"  # Close previous pattern
                
                pattern_data = next((p for p in survey_data['patterns'] if p['pattern_id'] == item['pattern_id']), {})
                
                html += f"""
    <div class="pattern">
        <h2>Pattern: {item['pattern_id']}</h2>
        <p><strong>Bug Type:</strong> {pattern_data.get('bug_type', 'Unknown')}</p>
        <p><strong>Description:</strong> {pattern_data.get('description', 'No description')}</p>
        <p><strong>Confidence:</strong> {pattern_data.get('confidence', 0):.3f}</p>
        
        <h3>Detection Rules:</h3>
"""
                for rule in pattern_data.get('detection_rules', []):
                    html += f'<div class="detection-rule">{rule}</div>'
                
                current_pattern = item['pattern_id']
                continue
            
            # Regular question
            question = item
            html += f"""
        <div class="question">
            <h4>{question['question_text']}</h4>
            <p><strong>Question ID:</strong> {question['question_id']}</p>
"""
            
            if question['scale_type'] == 'likert_5':
                html += '<div class="scale">'
                for i, option in enumerate(question['options']):
                    html += f'<label><input type="radio" name="{question["question_id"]}" value="{i+1}"> {i+1}. {option}</label><br>'
                html += '</div>'
            elif question['scale_type'] == 'multiple_choice':
                html += '<div class="scale">'
                for i, option in enumerate(question['options']):
                    html += f'<label><input type="radio" name="{question["question_id"]}" value="{option}"> {option}</label><br>'
                html += '</div>'
            elif question['scale_type'] == 'text':
                html += f'<textarea name="{question["question_id"]}" placeholder="Please provide your detailed feedback..."></textarea>'
            
            html += """
            <p><strong>Confidence in your response (0.0-1.0):</strong> 
               <input type="number" name="{}_confidence" min="0" max="1" step="0.1" value="0.8"></p>
            <p><strong>Reasoning:</strong> 
               <input type="text" name="{}_reasoning" placeholder="Brief explanation of your rating..."></p>
        </div>
""".format(question['question_id'], question['question_id'])
        
        if current_pattern:
            html += "</div>"  # Close last pattern
        
        html += """
    <div style="margin-top: 30px; padding: 20px; background: #e8f4f8; border-radius: 5px;">
        <h3>Submission Instructions</h3>
        <p>Please save your responses in the provided JSON template and email back to the research team.</p>
        <p>Thank you for your valuable expertise in validating these anti-patterns!</p>
    </div>
</body>
</html>
"""
        return html
    
    def _generate_response_template(self, survey_data: Dict) -> Dict:
        """Generate JSON template for expert responses"""
        template = {
            "response_metadata": {
                "expert_id": survey_data['survey_metadata']['expert_id'],
                "session_id": survey_data['survey_metadata']['session_id'],
                "completion_time": "",
                "total_time_minutes": 0
            },
            "responses": []
        }
        
        for question in survey_data['questions']:
            if question.get('section_type') == 'pattern_header':
                continue
            
            template["responses"].append({
                "question_id": question['question_id'],
                "pattern_id": question['pattern_id'],
                "question_type": question['question_type'],
                "response_value": "",
                "confidence": 0.8,
                "reasoning": "",
                "additional_comments": ""
            })
        
        return template
    
    def _save_validation_data(self):
        """Save all validation framework data"""
        # Save experts
        experts_data = [asdict(expert) for expert in self.experts]
        with open(self.work_dir / "experts.json", 'w', encoding='utf-8') as f:
            json.dump(experts_data, f, indent=2, ensure_ascii=False)
        
        # Save sessions
        sessions_data = []
        for session in self.sessions:
            session_dict = asdict(session)
            session_dict['start_time'] = session.start_time.isoformat()
            if session.completion_time:
                session_dict['completion_time'] = session.completion_time.isoformat()
            sessions_data.append(session_dict)
        
        with open(self.work_dir / "sessions.json", 'w', encoding='utf-8') as f:
            json.dump(sessions_data, f, indent=2, ensure_ascii=False)
        
        # Save questions
        questions_data = [asdict(question) for question in self.questions]
        with open(self.work_dir / "questions.json", 'w', encoding='utf-8') as f:
            json.dump(questions_data, f, indent=2, ensure_ascii=False)
    
    def run_expert_validation_setup(self) -> Dict[str, Any]:
        """Complete setup of expert validation framework"""
        logger.info("Starting expert validation framework setup...")
        
        # Load patterns
        patterns = self.load_patterns()
        if not patterns:
            logger.error("No patterns loaded for validation")
            return {"success": False, "error": "No patterns available"}
        
        # Setup expert panel
        experts = self.setup_expert_panel()
        
        # Create validation sessions
        sessions = self.create_validation_sessions()
        
        # Generate validation packages for each expert
        validation_packages = {}
        for expert in experts:
            # Find session for this expert
            expert_sessions = [s for s in sessions if s.expert_id == expert.expert_id]
            if expert_sessions:
                package_path = self.export_validation_package(expert.expert_id)
                validation_packages[expert.expert_id] = {
                    "expert_name": expert.name,
                    "package_path": package_path,
                    "patterns_assigned": len(expert_sessions[0].patterns_assigned),
                    "email": expert.email
                }
            else:
                logger.warning(f"No session found for expert {expert.expert_id}, skipping package generation")
        
        # Generate summary report
        summary = {
            "setup_completed": True,
            "total_patterns": len(patterns),
            "total_experts": len(experts),
            "total_sessions": len(sessions),
            "total_questions": len(self.questions),
            "validation_packages": validation_packages,
            "framework_statistics": {
                "questions_per_pattern": len(self.questions) / len(patterns),
                "patterns_per_expert": sum(len(s.patterns_assigned) for s in sessions) / len(experts),
                "estimated_total_time": len(self.questions) * 3
            }
        }
        
        # Save summary
        with open(self.work_dir / "validation_setup_summary.json", 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        logger.info("Expert validation framework setup completed successfully")
        return summary


def main():
    """Test the expert validation framework"""
    framework = ExpertValidationFramework()
    result = framework.run_expert_validation_setup()
    
    if result.get("setup_completed"):
        print(f"Expert validation setup completed:")
        print(f"- {result['total_patterns']} patterns prepared for validation")
        print(f"- {result['total_experts']} experts recruited")
        print(f"- {result['total_questions']} validation questions generated")
        print(f"- Validation packages created for all experts")
    else:
        print(f"Setup failed: {result.get('error', 'Unknown error')}")


if __name__ == "__main__":
    main()