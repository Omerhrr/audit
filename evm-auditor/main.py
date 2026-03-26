#!/usr/bin/env python3
"""
EVM Solidity Auditing Agent

Desktop auditing tool with deep Solidity/EVM reasoning, attacker mindset,
Python/Z3 verification, Slither static analysis, Foundry POCs/fuzzing,
and automated reporting.

Usage:
    python main.py [OPTIONS]
    
Options:
    --project PATH     Path to Solidity project directory
    --github URL       GitHub repository URL to clone and analyze
    --output PATH      Output directory for reports
    --model MODEL      LLM model to use (default: glm-4-plus)
    --llm-port PORT    Port for LLM API service (default: 3030)
    --no-slither       Disable Slither analysis
    --no-z3            Disable Z3 symbolic verification
    --no-foundry       Disable Foundry POC generation
    --headless         Run in headless mode (no GUI)
    --help             Show this help message
"""
import sys
import os
import argparse
import asyncio
from pathlib import Path
from datetime import datetime

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))


def check_dependencies():
    """Check and report on available dependencies"""
    deps_status = {}
    
    # Check PySide6
    try:
        import PySide6
        deps_status['PySide6'] = ('✓', 'installed')
    except ImportError:
        deps_status['PySide6'] = ('✗', 'not installed (required for GUI)')
    
    # Check aiohttp
    try:
        import aiohttp
        deps_status['aiohttp'] = ('✓', 'installed')
    except ImportError:
        deps_status['aiohttp'] = ('✗', 'not installed (required for LLM service)')
    
    # Check httpx
    try:
        import httpx
        deps_status['httpx'] = ('✓', 'installed')
    except ImportError:
        deps_status['httpx'] = ('✗', 'not installed (required for LLM client)')
    
    # Check slither
    try:
        import slither
        deps_status['slither'] = ('✓', 'installed')
    except ImportError:
        deps_status['slither'] = ('○', 'not installed (optional)')
    
    # Check z3
    try:
        import z3
        deps_status['z3-solver'] = ('✓', 'installed')
    except ImportError:
        deps_status['z3-solver'] = ('○', 'not installed (optional)')
    
    # Check web3
    try:
        import web3
        deps_status['web3'] = ('✓', 'installed')
    except ImportError:
        deps_status['web3'] = ('○', 'not installed (optional)')
    
    # Check foundry
    import subprocess
    try:
        result = subprocess.run(['forge', '--version'], capture_output=True, text=True)
        deps_status['foundry'] = ('✓', 'installed') if result.returncode == 0 else ('○', 'not installed (optional)')
    except FileNotFoundError:
        deps_status['foundry'] = ('○', 'not installed (optional)')
    
    return deps_status


def print_banner():
    """Print application banner"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     ███████╗██████╗  █████╗ ██╗    ██╗                       ║
║     ██╔════╝██╔══██╗██╔══██╗██║    ██║                       ║
║     █████╗  ██████╔╝███████║██║ █╗ ██║                       ║
║     ██╔══╝  ██╔══██╗██╔══██║██║███╗██║                       ║
║     ███████╗██║  ██║██║  ██║╚███╔███╔╝                       ║
║     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝                        ║
║                                                               ║
║     █████╗ ███████╗ ██████╗██╗██╗                            ║
║     ██╔══██╗██╔════╝██╔════╝██║██║                           ║
║     ███████║███████╗██║     ██║██║                           ║
║     ██╔══██║╚════██║██║     ██║██║                           ║
║     ██║  ██║███████║╚██████╗██║███████╗                      ║
║     ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝╚══════╝                      ║
║                                                               ║
║     █████╗ ██╗    ██╗███████╗███████╗ ██████╗ ███╗   ███╗    ║
║    ██╔══██╗██║    ██║██╔════╝██╔════╝██╔═══██╗████╗ ████║    ║
║    ███████║██║ █╗ ██║█████╗  █████╗  ██║   ██║██╔████╔██║    ║
║    ██╔══██║██║███╗██║██╔══╝  ██╔══╝  ██║   ██║██║╚██╔╝██║    ║
║    ██║  ██║╚███╔███╔╝███████╗██║     ╚██████╔╝██║ ╚═╝ ██║    ║
║    ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚═╝      ╚═════╝ ╚═╝     ╚═╝    ║
║                                                               ║
║              EVM Solidity Auditing Agent v1.0                 ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
""")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="EVM Solidity Auditing Agent - Desktop security auditing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                              # Launch GUI
  python main.py --headless -p ./contracts    # Analyze contracts in headless mode
  python main.py --check-deps                 # Check dependencies
        """
    )
    
    parser.add_argument(
        "--project", "-p",
        type=str,
        help="Path to Solidity project directory"
    )
    parser.add_argument(
        "--github", "-g",
        type=str,
        help="GitHub repository URL to clone and analyze"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="./reports",
        help="Output directory for reports (default: ./reports)"
    )
    parser.add_argument(
        "--model", "-m",
        type=str,
        default="glm-4-plus",
        help="LLM model to use (default: glm-4-plus)"
    )
    parser.add_argument(
        "--llm-port",
        type=int,
        default=3030,
        help="Port for LLM API service (default: 3030)"
    )
    parser.add_argument(
        "--no-slither",
        action="store_true",
        help="Disable Slither static analysis"
    )
    parser.add_argument(
        "--no-z3",
        action="store_true",
        help="Disable Z3 symbolic verification"
    )
    parser.add_argument(
        "--no-foundry",
        action="store_true",
        help="Disable Foundry POC generation"
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run in headless mode (no GUI)"
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=10,
        help="Maximum continuous audit iterations (default: 10)"
    )
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help="Check dependencies and exit"
    )
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Check dependencies if requested
    if args.check_deps:
        print("\nDependency Status:")
        print("-" * 50)
        deps = check_dependencies()
        for name, (status, note) in deps.items():
            print(f"  {status} {name:15} - {note}")
        print("-" * 50)
        print("\nLegend: ✓ installed | ○ optional | ✗ missing")
        return 0
    
    # Check dependencies
    deps = check_dependencies()
    missing_required = [k for k, (s, _) in deps.items() if s == '✗' and k in ['aiohttp', 'httpx']]
    
    if missing_required:
        print(f"\nError: Missing required dependencies: {', '.join(missing_required)}")
        print("Install with: pip install " + " ".join(missing_required))
        return 1
    
    if args.headless:
        # Run in headless mode
        return run_headless(args)
    else:
        # Check GUI dependencies
        if deps.get('PySide6', ('✗', ''))[0] == '✗':
            print("\nError: PySide6 is required for GUI mode.")
            print("Install with: pip install PySide6")
            print("Or use --headless mode for CLI operation.")
            return 1
        
        # Launch GUI
        return run_gui(args)


def run_gui(args):
    """Launch the GUI application"""
    try:
        from modules.ui.main_window import main as gui_main
        from modules.model.llm_service import create_model_brain
        
        # Store args for GUI to access
        os.environ["EVM_AUDITOR_LLM_PORT"] = str(args.llm_port)
        os.environ["EVM_AUDITOR_MODEL"] = args.model
        
        print(f"\nStarting GUI...")
        print(f"  LLM Service: http://localhost:{args.llm_port}")
        print(f"  Model: {args.model}")
        print()
        
        return gui_main()
        
    except ImportError as e:
        print(f"\nError loading GUI: {e}")
        print("Please ensure all dependencies are installed.")
        return 1


async def run_headless_analysis(
    project_path: Path,
    output_dir: Path,
    model: str,
    llm_port: int,
    use_slither: bool,
    use_z3: bool,
    use_foundry: bool,
    max_iterations: int
):
    """Run analysis in headless mode"""
    from modules.session.manager import session_manager
    from modules.parser.code_parser import solidity_parser
    from modules.model.llm_service import LLMClient, ModelBrain
    from modules.slither.analyzer import slither_analyzer
    from modules.foundry.test_runner import FoundryIntegration
    from modules.reporting.generator import report_generator
    from config import LeadStatus, Severity
    
    # Check Z3 availability
    z3_executor = None
    if use_z3:
        try:
            from modules.z3_solver.symbolic import z3_executor
        except ImportError:
            print("  Z3 not available, skipping symbolic verification")
    
    print(f"\n{'='*60}")
    print("Starting Headless Analysis")
    print(f"{'='*60}\n")
    
    # Create session
    print(f"[1/7] Creating session for: {project_path}")
    session = session_manager.create_session(
        name=project_path.name,
        project_path=str(project_path)
    )
    
    # Parse contracts
    print(f"[2/7] Parsing contracts...")
    results = solidity_parser.parse_directory(project_path)
    for result in results:
        for contract in result.contracts:
            session.contracts.append(contract)
            print(f"       Found: {contract.name} ({contract.kind})")
    
    print(f"       Total contracts: {len(session.contracts)}")
    
    if not session.contracts:
        print("Error: No contracts found in project")
        return None
    
    # Initialize LLM
    print(f"[3/7] Connecting to LLM service at http://localhost:{llm_port}...")
    llm_client = LLMClient(api_base_url=f"http://localhost:{llm_port}")
    model_brain = ModelBrain(llm_client, model)
    
    # Check LLM service health
    is_healthy = await llm_client.health_check()
    if not is_healthy:
        print(f"Warning: Cannot connect to LLM service. Start it with:")
        print(f"  python llm-service/llm_service.py --port {llm_port}")
        print("Continuing with limited analysis...")
    
    leads = []
    
    # Run Slither
    if use_slither:
        print(f"[4/7] Running Slither analysis...")
        try:
            for contract in session.contracts:
                contract_leads = slither_analyzer.analyze(Path(contract.file_path))
                leads.extend(contract_leads)
                print(f"       {contract.name}: {len(contract_leads)} leads")
            print(f"       Total Slither leads: {len(leads)}")
        except Exception as e:
            print(f"       Slither error: {e}")
    else:
        print(f"[4/7] Skipping Slither (disabled)")
    
    # LLM analysis
    print(f"[5/7] Running LLM analysis...")
    if is_healthy:
        for contract in session.contracts[:5]:  # Limit for reasonable runtime
            try:
                source = Path(contract.file_path).read_text()
                contract_leads = await model_brain.analyze_contract(contract, source)
                leads.extend(contract_leads)
                print(f"       {contract.name}: {len(contract_leads)} leads")
            except Exception as e:
                print(f"       Error analyzing {contract.name}: {e}")
        
        # Rank leads
        if leads:
            print(f"       Ranking {len(leads)} leads...")
            leads = await model_brain.rank_leads(leads)
    else:
        print(f"       Skipping (LLM service not available)")
    
    # Add leads to session
    for lead in leads:
        session.leads.append(lead)
    
    # Z3 verification
    if use_z3 and z3_executor:
        print(f"[6/7] Verifying leads with Z3...")
        for lead in [l for l in leads if l.confidence >= 0.5][:3]:
            try:
                for contract in session.contracts:
                    for func in contract.functions:
                        if func.name in lead.affected_functions:
                            result = z3_executor.verify_vulnerability(lead, func, contract)
                            if result.satisfiable:
                                lead.status = LeadStatus.TRIAGED
                                print(f"       {lead.title}: SATISFIABLE")
                            break
            except Exception as e:
                print(f"       Z3 error for {lead.id}: {e}")
    else:
        print(f"[6/7] Skipping Z3 verification (disabled or unavailable)")
    
    # Generate reports
    print(f"[7/7] Generating reports...")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    confirmed_leads = [l for l in session.leads if l.status == LeadStatus.TRIAGED or l.confidence >= 0.6]
    
    # Generate POCs
    if use_foundry and is_healthy:
        for lead in confirmed_leads[:3]:
            try:
                for contract in session.contracts:
                    if contract.name in lead.affected_contracts:
                        source = Path(contract.file_path).read_text()
                        poc = await model_brain.generate_foundry_poc(lead, contract, source)
                        lead.foundry_poc = poc
                        break
            except Exception as e:
                print(f"       POC generation error: {e}")
    
    # Create reports
    reports = []
    for lead in confirmed_leads:
        report = report_generator.generate_report(lead, lead.foundry_poc or "")
        reports.append(report)
    
    # Save reports
    if reports:
        report_path = report_generator.generate_session_report(
            session.to_dict(),
            reports,
            format="markdown"
        )
        print(f"       Report saved: {report_path}")
    else:
        print(f"       No confirmed vulnerabilities to report")
    
    # Summary
    print(f"\n{'='*60}")
    print("Analysis Complete")
    print(f"{'='*60}")
    print(f"Total Contracts: {len(session.contracts)}")
    print(f"Total Leads: {len(session.leads)}")
    print(f"High Confidence: {len([l for l in session.leads if l.confidence >= 0.6])}")
    
    # Severity breakdown
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = len([l for l in session.leads if l.severity == severity])
        if count > 0:
            print(f"  {severity.value}: {count}")
    
    print(f"\nReports saved to: {output_dir}")
    
    return session


def run_headless(args):
    """Run in headless mode"""
    if not args.project:
        print("Error: --project path is required in headless mode")
        print("Usage: python main.py --headless --project ./my-contracts")
        return 1
    
    project_path = Path(args.project)
    if not project_path.exists():
        print(f"Error: Project path does not exist: {project_path}")
        return 1
    
    output_dir = Path(args.output)
    
    # Run async analysis
    asyncio.run(run_headless_analysis(
        project_path=project_path,
        output_dir=output_dir,
        model=args.model,
        llm_port=args.llm_port,
        use_slither=not args.no_slither,
        use_z3=not args.no_z3,
        use_foundry=not args.no_foundry,
        max_iterations=args.max_iterations
    ))
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
