"""
Linux Documentation RAG System
Loads Linux kernel documentation into vector database for context-aware anti-pattern detection
"""
import os
from pathlib import Path
from typing import List, Dict, Any
import chromadb
from chromadb.config import Settings
import requests
from loguru import logger
from sentence_transformers import SentenceTransformer
import re


class LinuxDocsRAG:
    def __init__(self, db_path: str = "data/vector_db"):
        """Initialize Linux documentation RAG system"""
        self.db_path = Path(db_path)
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize ChromaDB
        self.client = chromadb.PersistentClient(
            path=str(self.db_path),
            settings=Settings(allow_reset=True)
        )
        
        # Initialize embedding model
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Create collection
        try:
            self.collection = self.client.get_collection("linux_docs")
            logger.info("Loaded existing Linux docs collection")
        except:
            self.collection = self.client.create_collection(
                name="linux_docs",
                metadata={"description": "Linux kernel documentation"}
            )
            logger.info("Created new Linux docs collection")
    
    def download_linux_docs(self) -> Dict[str, str]:
        """Download key Linux kernel documentation files"""
        docs_urls = {
            "CodingStyle": "https://raw.githubusercontent.com/torvalds/linux/master/Documentation/process/coding-style.rst",
            "SubmittingPatches": "https://raw.githubusercontent.com/torvalds/linux/master/Documentation/process/submitting-patches.rst",
            "SecurityBugs": "https://raw.githubusercontent.com/torvalds/linux/master/Documentation/admin-guide/security-bugs.rst",
            "KernelHacking": "https://raw.githubusercontent.com/torvalds/linux/master/Documentation/process/kernel-docs.rst",
            "MemoryManagement": "https://raw.githubusercontent.com/torvalds/linux/master/Documentation/core-api/memory-allocation.rst",
            "Locking": "https://raw.githubusercontent.com/torvalds/linux/master/Documentation/locking/lockdep-design.rst",
            "ErrorHandling": "https://raw.githubusercontent.com/torvalds/linux/master/Documentation/process/maintainer-netdev.rst"
        }
        
        docs_content = {}
        for doc_name, url in docs_urls.items():
            try:
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    docs_content[doc_name] = response.text
                    logger.info(f"Downloaded {doc_name}")
                else:
                    logger.warning(f"Failed to download {doc_name}: {response.status_code}")
            except Exception as e:
                logger.error(f"Error downloading {doc_name}: {e}")
        
        return docs_content
    
    def chunk_document(self, text: str, chunk_size: int = 1000, overlap: int = 100) -> List[str]:
        """Split document into overlapping chunks"""
        # Clean and normalize text
        text = re.sub(r'\n+', '\n', text)
        text = re.sub(r'\s+', ' ', text)
        
        chunks = []
        start = 0
        
        while start < len(text):
            end = start + chunk_size
            if end >= len(text):
                chunks.append(text[start:])
                break
            
            # Try to break at sentence boundary
            last_period = text.rfind('.', start, end)
            if last_period > start:
                end = last_period + 1
            
            chunks.append(text[start:end])
            start = end - overlap
        
        return [chunk.strip() for chunk in chunks if chunk.strip()]
    
    def populate_vector_db(self):
        """Download docs and populate vector database"""
        logger.info("Downloading Linux documentation...")
        docs_content = self.download_linux_docs()
        
        if not docs_content:
            logger.error("No documentation downloaded!")
            return
        
        all_chunks = []
        all_metadata = []
        all_ids = []
        chunk_id = 0
        
        for doc_name, content in docs_content.items():
            logger.info(f"Processing {doc_name}...")
            chunks = self.chunk_document(content)
            
            for i, chunk in enumerate(chunks):
                all_chunks.append(chunk)
                all_metadata.append({
                    "document": doc_name,
                    "chunk_id": i,
                    "length": len(chunk)
                })
                all_ids.append(f"{doc_name}_{i}")
                chunk_id += 1
        
        if all_chunks:
            logger.info(f"Adding {len(all_chunks)} chunks to vector database...")
            
            # Generate embeddings
            embeddings = self.embedding_model.encode(all_chunks).tolist()
            
            # Add to ChromaDB
            self.collection.add(
                documents=all_chunks,
                metadatas=all_metadata,
                ids=all_ids,
                embeddings=embeddings
            )
            
            logger.info(f"Successfully added {len(all_chunks)} chunks to vector database")
        else:
            logger.error("No chunks to add to database!")
    
    def query_context(self, query: str, n_results: int = 5) -> List[str]:
        """Query vector database for relevant Linux kernel context"""
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results
            )
            
            if results['documents'][0]:
                contexts = results['documents'][0]
                logger.debug(f"Found {len(contexts)} relevant context chunks")
                return contexts
            else:
                logger.warning("No relevant context found")
                return []
                
        except Exception as e:
            logger.error(f"Error querying vector database: {e}")
            return []
    
    def get_antipattern_context(self, commit_diffs: List[str]) -> str:
        """Get Linux-specific context for anti-pattern analysis"""
        # Create query from commit diffs
        query = " ".join(commit_diffs)[:1000]  # Limit query length
        
        # Add specific anti-pattern keywords
        antipattern_keywords = [
            "memory leak", "use after free", "buffer overflow", 
            "race condition", "deadlock", "locking", "cleanup",
            "error handling", "resource management", "initialization"
        ]
        
        enhanced_query = f"{query} {' '.join(antipattern_keywords)}"
        
        # Query vector database
        contexts = self.query_context(enhanced_query, n_results=3)
        
        if contexts:
            return "\n\n".join(contexts)
        else:
            return "No specific Linux kernel context found."


def main():
    """Test the RAG system"""
    rag = LinuxDocsRAG()
    
    # Populate database if empty
    if rag.collection.count() == 0:
        rag.populate_vector_db()
    
    # Test query
    test_query = "memory management error handling in kernel"
    context = rag.get_antipattern_context([test_query])
    print(f"Context for '{test_query}':")
    print(context[:500] + "...")


if __name__ == "__main__":
    main()