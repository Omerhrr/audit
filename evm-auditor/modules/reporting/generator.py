"""
Reporting Module for EVM Solidity Auditing Agent

Generates structured reports with confirmed bugs, POCs, severity, and mitigation suggestions.
Supports Markdown, PDF, and JSON output formats.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
import uuid

from models import VulnerabilityLead, BugReport, ContractInfo
from config import Severity, REPORTS_DIR


@dataclass
class ReportMetadata:
    """Metadata for a report"""
    title: str
    project_name: str
    auditor: str
    date: str
    version: str = "1.0"
    executive_summary: str = ""


class MarkdownReporter:
    """Generates Markdown reports"""
    
    @staticmethod
    def generate_bug_report(report: BugReport) -> str:
        """Generate a single bug report in Markdown"""
        md = f"""# {report.title}

| Field | Value |
|-------|-------|
| **Severity** | {report.severity.value} |
| **Likelihood** | {report.likelihood} |
| **Status** | Confirmed |
| **Date** | {report.created_at.strftime('%Y-%m-%d %H:%M')} |

## Description

{report.description}

## Impact

{report.impact}

## Affected Contracts

"""
        for contract in report.affected_contracts:
            md += f"- `{contract}`\n"
        
        md += "\n## Affected Functions\n\n"
        for func in report.affected_functions:
            md += f"- `{func}()`\n"
        
        md += f"""
## Attack Vector

{report.attack_vector}

## Preconditions

"""
        for precond in report.preconditions:
            md += f"- {precond}\n"
        
        md += "\n## Attack Steps\n\n"
        for i, step in enumerate(report.attack_steps, 1):
            md += f"{i}. {step}\n"
        
        if report.poc_code:
            md += f"""
## Proof of Concept

```solidity
{report.poc_code}
```

"""
        
        md += f"""## Mitigation

{report.mitigation}

## Recommendation

{report.recommendation}

"""
        
        if report.references:
            md += "## References\n\n"
            for ref in report.references:
                md += f"- {ref}\n"
        
        return md
    
    @staticmethod
    def generate_full_report(
        metadata: ReportMetadata,
        bug_reports: List[BugReport],
        session_summary: Dict[str, Any]
    ) -> str:
        """Generate a complete audit report in Markdown"""
        
        # Count by severity
        severity_counts = {s.value: 0 for s in Severity}
        for report in bug_reports:
            severity_counts[report.severity.value] += 1
        
        md = f"""# {metadata.title}

**Project:** {metadata.project_name}  
**Auditor:** {metadata.auditor}  
**Date:** {metadata.date}  
**Version:** {metadata.version}

---

## Executive Summary

{metadata.executive_summary}

## Summary of Findings

| Severity | Count |
|----------|-------|
"""
        
        for severity in ["Critical", "High", "Medium", "Low", "Informational", "Gas Optimization"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                md += f"| {severity} | {count} |\n"
        
        md += f"""
## Audit Statistics

- **Total Functions Analyzed:** {session_summary.get('total_functions', 'N/A')}
- **Vulnerability Leads Generated:** {session_summary.get('leads_count', 'N/A')}
- **Confirmed Vulnerabilities:** {session_summary.get('confirmed_count', 'N/A')}
- **Audit Iterations:** {session_summary.get('audit_iterations', 'N/A')}

---

## Detailed Findings

"""
        
        # Add each bug report
        for i, report in enumerate(bug_reports, 1):
            md += f"### Finding {i}: {report.title}\n\n"
            md += MarkdownReporter.generate_bug_report(report)
            md += "\n---\n\n"
        
        return md


class JSONReporter:
    """Generates JSON reports"""
    
    @staticmethod
    def generate_report(
        metadata: ReportMetadata,
        bug_reports: List[BugReport],
        session_summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate a complete audit report in JSON format"""
        
        return {
            "metadata": {
                "title": metadata.title,
                "project_name": metadata.project_name,
                "auditor": metadata.auditor,
                "date": metadata.date,
                "version": metadata.version,
                "executive_summary": metadata.executive_summary,
            },
            "summary": {
                "total_findings": len(bug_reports),
                "severity_counts": {
                    s.value: len([r for r in bug_reports if r.severity == s])
                    for s in Severity
                },
                "session_statistics": session_summary,
            },
            "findings": [report.to_dict() for report in bug_reports],
            "generated_at": datetime.now().isoformat(),
        }


class PDFReporter:
    """Generates PDF reports"""
    
    @staticmethod
    def generate_report(
        metadata: ReportMetadata,
        bug_reports: List[BugReport],
        session_summary: Dict[str, Any],
        output_path: Path
    ) -> bool:
        """Generate a PDF report using reportlab or weasyprint"""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, 
                TableStyle, PageBreak, Preformatted
            )
            
            # Create document
            doc = SimpleDocTemplate(
                str(output_path),
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )
            
            # Styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
            )
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=14,
                spaceAfter=12,
            )
            body_style = styles['Normal']
            code_style = ParagraphStyle(
                'Code',
                parent=styles['Code'],
                fontSize=8,
                backColor=colors.Color(0.95, 0.95, 0.95),
            )
            
            # Build content
            story = []
            
            # Title page
            story.append(Paragraph(metadata.title, title_style))
            story.append(Spacer(1, 12))
            story.append(Paragraph(f"<b>Project:</b> {metadata.project_name}", body_style))
            story.append(Paragraph(f"<b>Auditor:</b> {metadata.auditor}", body_style))
            story.append(Paragraph(f"<b>Date:</b> {metadata.date}", body_style))
            story.append(Spacer(1, 24))
            
            # Executive summary
            story.append(Paragraph("Executive Summary", heading_style))
            story.append(Paragraph(metadata.executive_summary, body_style))
            story.append(Spacer(1, 24))
            
            # Severity summary table
            story.append(Paragraph("Summary of Findings", heading_style))
            
            severity_counts = {s.value: 0 for s in Severity}
            for report in bug_reports:
                severity_counts[report.severity.value] += 1
            
            table_data = [["Severity", "Count"]]
            for severity in ["Critical", "High", "Medium", "Low", "Informational", "Gas Optimization"]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    table_data.append([severity, str(count)])
            
            table = Table(table_data, colWidths=[2*inch, 1*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(table)
            story.append(PageBreak())
            
            # Detailed findings
            story.append(Paragraph("Detailed Findings", heading_style))
            
            for i, report in enumerate(bug_reports, 1):
                # Finding title
                story.append(Paragraph(f"Finding {i}: {report.title}", heading_style))
                
                # Finding details table
                details_data = [
                    ["Severity", report.severity.value],
                    ["Likelihood", report.likelihood],
                    ["Affected Contracts", ", ".join(report.affected_contracts)],
                ]
                details_table = Table(details_data, colWidths=[2*inch, 4*inch])
                details_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                story.append(details_table)
                story.append(Spacer(1, 12))
                
                # Description
                story.append(Paragraph("<b>Description:</b>", body_style))
                story.append(Paragraph(report.description, body_style))
                story.append(Spacer(1, 12))
                
                # Impact
                story.append(Paragraph("<b>Impact:</b>", body_style))
                story.append(Paragraph(report.impact, body_style))
                story.append(Spacer(1, 12))
                
                # Mitigation
                story.append(Paragraph("<b>Mitigation:</b>", body_style))
                story.append(Paragraph(report.mitigation, body_style))
                
                story.append(Spacer(1, 24))
            
            # Build PDF
            doc.build(story)
            return True
            
        except ImportError:
            print("reportlab not installed. Install with: pip install reportlab")
            return False
        except Exception as e:
            print(f"Error generating PDF: {e}")
            return False


class ReportGenerator:
    """
    Main report generator that coordinates report creation.
    
    Features:
    - Generate reports in multiple formats
    - Include POC code and verification details
    - Customize report templates
    """
    
    def __init__(self, output_dir: Path = REPORTS_DIR):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(
        self,
        lead: VulnerabilityLead,
        poc_code: str = "",
        output_format: str = "markdown"
    ) -> BugReport:
        """Generate a bug report from a vulnerability lead"""
        
        report = BugReport(
            id=str(uuid.uuid4())[:8],
            title=lead.title,
            lead=lead,
            description=lead.description,
            severity=lead.severity,
            impact=lead.impact,
            likelihood=self._calculate_likelihood(lead),
            affected_contracts=lead.affected_contracts,
            affected_functions=lead.affected_functions,
            attack_vector=lead.attack_vector,
            preconditions=lead.preconditions,
            attack_steps=lead.attack_steps,
            poc_code=poc_code,
        )
        
        return report
    
    def _calculate_likelihood(self, lead: VulnerabilityLead) -> str:
        """Calculate likelihood based on confidence and preconditions"""
        if lead.confidence >= 0.8:
            return "High"
        elif lead.confidence >= 0.5:
            return "Medium"
        else:
            return "Low"
    
    def save_report(
        self,
        report: BugReport,
        format: str = "markdown"
    ) -> Optional[Path]:
        """Save a bug report to file"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"bug_{report.id}_{timestamp}"
        
        if format == "markdown" or format == "md":
            output_path = self.output_dir / f"{filename}.md"
            content = MarkdownReporter.generate_bug_report(report)
            output_path.write_text(content)
            return output_path
            
        elif format == "json":
            output_path = self.output_dir / f"{filename}.json"
            content = json.dumps(report.to_dict(), indent=2)
            output_path.write_text(content)
            return output_path
            
        elif format == "pdf":
            output_path = self.output_dir / f"{filename}.pdf"
            # Create minimal metadata for single report
            metadata = ReportMetadata(
                title=report.title,
                project_name=report.affected_contracts[0] if report.affected_contracts else "Unknown",
                auditor="EVM Solidity Auditor",
                date=datetime.now().strftime("%Y-%m-%d"),
            )
            if PDFReporter.generate_report(metadata, [report], {}, output_path):
                return output_path
        
        return None
    
    def generate_session_report(
        self,
        session_data: Dict[str, Any],
        bug_reports: List[BugReport],
        format: str = "markdown"
    ) -> Optional[Path]:
        """Generate a complete session report"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        project_name = session_data.get("name", "Audit")
        filename = f"audit_report_{project_name}_{timestamp}"
        
        metadata = ReportMetadata(
            title=f"Security Audit Report: {project_name}",
            project_name=project_name,
            auditor="EVM Solidity Auditor Agent",
            date=datetime.now().strftime("%Y-%m-%d"),
            executive_summary=self._generate_executive_summary(bug_reports),
        )
        
        session_summary = {
            "total_functions": session_data.get("total_functions", 0),
            "leads_count": session_data.get("leads_count", 0),
            "confirmed_count": len(bug_reports),
            "audit_iterations": session_data.get("audit_iterations", 0),
        }
        
        if format == "markdown" or format == "md":
            output_path = self.output_dir / f"{filename}.md"
            content = MarkdownReporter.generate_full_report(metadata, bug_reports, session_summary)
            output_path.write_text(content)
            return output_path
            
        elif format == "json":
            output_path = self.output_dir / f"{filename}.json"
            content = JSONReporter.generate_report(metadata, bug_reports, session_summary)
            output_path.write_text(json.dumps(content, indent=2))
            return output_path
            
        elif format == "pdf":
            output_path = self.output_dir / f"{filename}.pdf"
            if PDFReporter.generate_report(metadata, bug_reports, session_summary, output_path):
                return output_path
        
        return None
    
    def _generate_executive_summary(self, bug_reports: List[BugReport]) -> str:
        """Generate an executive summary from bug reports"""
        
        if not bug_reports:
            return "No vulnerabilities were confirmed during this audit."
        
        critical = len([r for r in bug_reports if r.severity == Severity.CRITICAL])
        high = len([r for r in bug_reports if r.severity == Severity.HIGH])
        medium = len([r for r in bug_reports if r.severity == Severity.MEDIUM])
        low = len([r for r in bug_reports if r.severity == Severity.LOW])
        
        summary_parts = [f"This audit identified {len(bug_reports)} confirmed vulnerabilities."]
        
        if critical > 0:
            summary_parts.append(f"This includes {critical} critical-severity issue(s) that require immediate attention.")
        if high > 0:
            summary_parts.append(f"There are {high} high-severity vulnerabilities that should be addressed before deployment.")
        if medium > 0:
            summary_parts.append(f"Additionally, {medium} medium-severity issues were found.")
        if low > 0:
            summary_parts.append(f"{low} low-severity informational findings were also noted.")
        
        summary_parts.append("\n\nThe most critical findings relate to:")
        
        # Add top 3 critical/high issues
        critical_issues = [r for r in bug_reports if r.severity in (Severity.CRITICAL, Severity.HIGH)][:3]
        for issue in critical_issues:
            summary_parts.append(f"\n- **{issue.title}**: {issue.description[:100]}...")
        
        return " ".join(summary_parts)


# Singleton instance
report_generator = ReportGenerator()
