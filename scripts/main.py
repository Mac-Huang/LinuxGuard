"""
LinuxGuard Main Orchestrator
Coordinates the complete anti-pattern detection pipeline
"""
import os
import sys
from pathlib import Path
import argparse
from loguru import logger
import time
from typing import List

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))

from config import config
from src.data_collection.linux_docs_rag import LinuxDocsRAG
from src.data_collection.commit_processor import CommitProcessor
from src.data_collection.antipattern_filter import AntiPatternFilter


class LinuxGuardOrchestrator:
    """Main orchestrator for LinuxGuard pipeline"""
    
    def __init__(self):
        """Initialize the orchestrator"""
        self.config = config
        
        # Validate configuration
        if not self.config.validate():
            logger.error("Configuration validation failed")
            sys.exit(1)
        
        # Initialize components
        self.rag_system = None
        self.commit_processor = None
        self.antipattern_filter = None
        
        logger.info("LinuxGuard Orchestrator initialized")
    
    def setup_rag_system(self):
        """Initialize and populate RAG system"""
        logger.info("Setting up RAG system...")
        
        self.rag_system = LinuxDocsRAG(db_path=self.config.rag.vector_db_path)
        
        # Check if database is already populated
        if self.rag_system.collection.count() == 0:
            logger.info("RAG database empty, populating with Linux documentation...")
            self.rag_system.populate_vector_db()
        else:
            logger.info(f"RAG database already contains {self.rag_system.collection.count()} documents")
        
        logger.info("RAG system setup complete")
    
    def setup_commit_processor(self):
        """Initialize commit processor"""
        logger.info("Setting up commit processor...")
        
        repo_path = self.config.processing.repo_path
        if not Path(repo_path).exists():
            logger.error(f"Repository path does not exist: {repo_path}")
            logger.info("Please clone the Linux kernel repository first:")
            logger.info(f"git clone --depth 500 https://github.com/torvalds/linux.git {repo_path}")
            return False
        
        self.commit_processor = CommitProcessor(
            repo_path=repo_path,
            output_dir=str(self.config.data_dir / "commits")
        )
        
        logger.info("Commit processor setup complete")
        return True
    
    def setup_antipattern_filter(self):
        """Initialize anti-pattern filter"""
        logger.info("Setting up anti-pattern filter...")
        
        self.antipattern_filter = AntiPatternFilter(
            api_key=self.config.llm.api_key,
            model_name=self.config.llm.model_name
        )
        
        logger.info("Anti-pattern filter setup complete")
    
    def run_phase_a(self) -> bool:
        """Execute Phase A: Anti-pattern dataset creation"""
        logger.info("=" * 60)
        logger.info("PHASE A: ANTI-PATTERN DATASET CREATION")
        logger.info("=" * 60)
        
        # Step 1: Setup RAG system
        self.setup_rag_system()
        
        # Step 2: Setup commit processor
        if not self.setup_commit_processor():
            return False
        
        # Step 3: Process commits
        logger.info("Processing commits...")
        start_time = time.time()
        
        batches = self.commit_processor.process_commits(
            days_back=self.config.processing.days_back,
            batch_size=self.config.processing.batch_size
        )
        
        processing_time = time.time() - start_time
        logger.info(f"Commit processing completed in {processing_time:.1f} seconds")
        logger.info(f"Created {len(batches)} batches for analysis")
        
        # Step 4: Setup anti-pattern filter
        self.setup_antipattern_filter()
        
        # Step 5: Filter for anti-patterns
        logger.info("Filtering commits for anti-patterns...")
        start_time = time.time()
        
        results = self.antipattern_filter.filter_antipatterns(batches)
        
        filtering_time = time.time() - start_time
        logger.info(f"Anti-pattern filtering completed in {filtering_time:.1f} seconds")
        
        # Step 6: Save results
        self.antipattern_filter.save_results(results)
        
        # Step 7: Generate report
        report = self.antipattern_filter.generate_summary_report(results)
        
        report_path = self.config.data_dir / "phase_a_report.md"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        logger.info(f"Phase A report saved to: {report_path}")
        
        # Summary
        antipatterns_found = len([r for r in results if r.is_antipattern])
        logger.info("=" * 60)
        logger.info("PHASE A COMPLETE")
        logger.info(f"Total commits processed: {sum(len(batch) for batch in batches)}")
        logger.info(f"Anti-patterns identified: {antipatterns_found}")
        logger.info(f"Processing time: {processing_time:.1f}s")
        logger.info(f"Filtering time: {filtering_time:.1f}s")
        logger.info("=" * 60)
        
        return True
    
    def run_phase_b(self):
        """Execute Phase B: Pattern analysis and checker generation"""
        logger.info("=" * 60)
        logger.info("PHASE B: PATTERN ANALYSIS & CHECKER GENERATION")
        logger.info("=" * 60)
        
        # Load Phase A results
        if not self.antipattern_filter:
            self.setup_antipattern_filter()
        
        results = self.antipattern_filter.load_results()
        if not results:
            logger.error("No Phase A results found. Run Phase A first.")
            return False
        
        antipatterns = [r for r in results if r.is_antipattern and r.confidence >= self.config.processing.confidence_threshold]
        logger.info(f"Found {len(antipatterns)} high-confidence anti-patterns for analysis")
        
        # TODO: Implement Phase B components
        logger.warning("Phase B implementation is in progress...")
        logger.info("Phase B will include:")
        logger.info("1. Anti-pattern principle derivation")
        logger.info("2. Clang static analyzer generation")
        logger.info("3. Multi-version Linux validation")
        
        return True
    
    def run_full_pipeline(self):
        """Execute complete LinuxGuard pipeline"""
        logger.info("Starting complete LinuxGuard pipeline...")
        
        start_time = time.time()
        
        # Execute Phase A
        if not self.run_phase_a():
            logger.error("Phase A failed, aborting pipeline")
            return False
        
        # Execute Phase B
        if not self.run_phase_b():
            logger.error("Phase B failed")
            return False
        
        total_time = time.time() - start_time
        logger.info(f"Complete pipeline finished in {total_time:.1f} seconds")
        
        return True


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="LinuxGuard: Anti-Pattern Detection for Linux Kernel")
    parser.add_argument(
        "--phase", 
        choices=["a", "b", "full"], 
        default="full",
        help="Phase to execute: a (dataset creation), b (analysis), or full (both)"
    )
    parser.add_argument(
        "--config", 
        default="config.yaml",
        help="Configuration file path"
    )
    parser.add_argument(
        "--verbose", 
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = "DEBUG" if args.verbose else "INFO"
    logger.remove()
    logger.add(
        sys.stderr,
        level=log_level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    )
    
    # Also log to file
    logger.add(
        "linuxguard.log",
        level="DEBUG",
        rotation="10 MB",
        retention="7 days"
    )
    
    # Initialize orchestrator
    orchestrator = LinuxGuardOrchestrator()
    
    # Execute requested phase
    try:
        if args.phase == "a":
            success = orchestrator.run_phase_a()
        elif args.phase == "b":
            success = orchestrator.run_phase_b()
        else:  # full
            success = orchestrator.run_full_pipeline()
        
        if success:
            logger.info("LinuxGuard execution completed successfully")
            sys.exit(0)
        else:
            logger.error("LinuxGuard execution failed")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logger.warning("Execution interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()