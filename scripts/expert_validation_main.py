"""
Expert Validation Main Script
Orchestrates the expert validation process for LinuxGuard anti-patterns
"""
import sys
from pathlib import Path
from loguru import logger
import json

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))

from src.validation.expert_validation import ExpertValidationFramework


def main():
    """Main entry point for expert validation"""
    logger.info("=== LinuxGuard Expert Validation Framework ===")
    
    # Initialize framework
    framework = ExpertValidationFramework()
    
    # Run complete setup
    logger.info("Setting up expert validation...")
    result = framework.run_expert_validation_setup()
    
    if result.get("setup_completed"):
        print("\n" + "="*60)
        print("EXPERT VALIDATION FRAMEWORK: SETUP COMPLETE [SUCCESS]")
        print("="*60)
        
        print(f"\n[STATS] Validation Statistics:")
        print(f"   - Patterns prepared: {result['total_patterns']}")
        print(f"   - Security experts recruited: {result['total_experts']}")
        print(f"   - Validation questions generated: {result['total_questions']}")
        print(f"   - Average questions per pattern: {result['framework_statistics']['questions_per_pattern']:.1f}")
        print(f"   - Average patterns per expert: {result['framework_statistics']['patterns_per_expert']:.1f}")
        print(f"   - Estimated total validation time: {result['framework_statistics']['estimated_total_time']} minutes")
        
        print(f"\n[EXPERTS] Expert Panel:")
        for expert_id, package_info in result['validation_packages'].items():
            print(f"   - {package_info['expert_name']}: {package_info['patterns_assigned']} patterns assigned")
            print(f"     Package: {package_info['package_path']}")
        
        print(f"\n[NEXT] Next Steps:")
        print(f"   1. Review validation packages in: data/expert_validation/")
        print(f"   2. Send packages to experts via email or survey platform")
        print(f"   3. Collect responses over 14-day validation period")
        print(f"   4. Analyze expert consensus and pattern validity")
        
        print(f"\n[OUTCOMES] Expected Outcomes:")
        print(f"   - Pattern relevance validation (5-point scale)")
        print(f"   - Accuracy assessment for each anti-pattern")
        print(f"   - Severity impact evaluation")
        print(f"   - False positive likelihood estimation")
        print(f"   - Practical utility assessment")
        print(f"   - Expert feedback for pattern improvement")
        
        # Generate deployment instructions
        generate_deployment_instructions(result)
        
    else:
        print(f"[ERROR] Expert validation setup failed: {result.get('error', 'Unknown error')}")
        return False
    
    return True


def generate_deployment_instructions(validation_result):
    """Generate instructions for deploying expert validation"""
    
    instructions = f"""# Expert Validation Deployment Instructions

## Overview
LinuxGuard expert validation framework has been successfully set up with {validation_result['total_experts']} security experts to validate {validation_result['total_patterns']} anti-patterns.

## Expert Panel
"""
    
    for expert_id, package_info in validation_result['validation_packages'].items():
        instructions += f"""
### {package_info['expert_name']}
- **Email**: {package_info['email']}
- **Patterns assigned**: {package_info['patterns_assigned']}
- **Package location**: `{package_info['package_path']}`
- **Files included**:
  - `validation_survey.html` - Human-readable survey
  - `validation_survey.json` - Machine-readable questions
  - `response_template.json` - Response format template

"""
    
    instructions += f"""
## Deployment Process

### Step 1: Package Review
Review each expert's validation package:
```bash
# Navigate to expert packages
cd data/expert_validation/

# Review packages for each expert
ls expert_*/
```

### Step 2: Email Distribution
Send personalized emails to each expert with:

**Subject**: Expert Validation Request - LinuxGuard Security Pattern Analysis

**Body Template**:
```
Dear [Expert Name],

We are conducting a research study on automated security pattern detection for the Linux kernel and would greatly value your expert opinion.

**Background**: Our LinuxGuard system has derived {validation_result['total_patterns']} anti-patterns from Linux kernel vulnerability commits using LLM analysis. We need expert validation to ensure these patterns represent genuine security concerns.

**Your Task**: Please evaluate the attached anti-patterns using your security expertise. The process involves:
- Reviewing pattern descriptions and detection rules
- Rating relevance, accuracy, and severity
- Providing feedback for improvement

**Time Required**: Approximately {validation_result['framework_statistics']['estimated_total_time'] // validation_result['total_experts']} minutes
**Deadline**: 14 days from today
**Compensation**: Academic acknowledgment and co-authorship consideration

**Files Attached**:
- validation_survey.html (human-readable survey)
- response_template.json (for submitting responses)

Please complete the survey and return the filled response_template.json file.

Thank you for contributing to advancing automated security analysis!

Best regards,
LinuxGuard Research Team
```

### Step 3: Response Collection
- Monitor responses in expert directories
- Send reminders at 3, 7, and 10 days if needed
- Track completion status

### Step 4: Analysis Pipeline
Once responses are collected:
```python
from src.validation.expert_analysis import ExpertResponseAnalyzer
analyzer = ExpertResponseAnalyzer()
consensus_results = analyzer.analyze_expert_consensus()
```

## Quality Assurance

### Validation Criteria
- **Minimum responses**: {validation_result['framework_statistics'].get('min_experts_per_pattern', 3)} experts per pattern
- **Response quality**: Confidence scores ≥ 0.6
- **Consensus threshold**: Agreement among ≥60% of experts
- **Feedback integration**: Qualitative improvements from expert comments

### Success Metrics
- **Response rate**: Target ≥80% expert participation
- **Pattern validation**: ≥70% patterns confirmed as relevant
- **Inter-rater reliability**: Cronbach's α ≥ 0.7
- **Actionable feedback**: Concrete improvement suggestions

## Timeline
- **Week 1**: Package distribution and initial responses
- **Week 2**: Reminder emails and response collection
- **Week 3**: Response analysis and consensus calculation
- **Week 4**: Pattern refinement based on expert feedback

## Risk Mitigation
- **Low response rate**: Follow-up with non-respondents, extend deadline if needed
- **Conflicting opinions**: Analyze disagreement patterns, seek additional expert input
- **Technical issues**: Provide alternative response methods (email, phone interview)

---

**Status**: Framework ready for deployment ✅
**Next Action**: Begin expert outreach and package distribution
"""
    
    # Save instructions
    with open("data/expert_validation/DEPLOYMENT_INSTRUCTIONS.md", 'w', encoding='utf-8') as f:
        f.write(instructions)
    
    print(f"\n[DOCS] Deployment instructions saved to: data/expert_validation/DEPLOYMENT_INSTRUCTIONS.md")


if __name__ == "__main__":
    success = main()
    if success:
        logger.info("Expert validation framework ready for deployment")
    else:
        logger.error("Expert validation framework setup failed")
        sys.exit(1)