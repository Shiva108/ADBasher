#!/usr/bin/env python3
"""
Module Syntax Validation Script
Validates Python syntax for all ADBasher modules
"""
import os
import py_compile
import sys
from pathlib import Path


def validate_python_files(root_dir):
    """Validate all Python files in directory"""
    print(f"[*] Validating Python files in {root_dir}")
    
    errors = []
    file_count = 0
    
    for py_file in Path(root_dir).rglob("*.py"):
        # Skip __pycache__ and .pyc files
        if '__pycache__' in str(py_file) or py_file.suffix == '.pyc':
            continue
        
        file_count += 1
        try:
            py_compile.compile(str(py_file), doraise=True)
            print(f"[+] {py_file.relative_to(root_dir)}")
        except py_compile.PyCompileError as e:
            errors.append((str(py_file), str(e)))
            print(f"[!] {py_file.relative_to(root_dir)}: SYNTAX ERROR")
    
    print(f"\n{'='*60}")
    print(f"Total files checked: {file_count}")
    print(f"Syntax errors: {len(errors)}")
    
    if errors:
        print(f"\n[!] Files with syntax errors:")
        for file_path, error in errors:
            print(f"  - {file_path}")
            print(f"    {error}")
        return False
    else:
        print(f"\n[✓] All Python files have valid syntax")
        return True


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "/home/e/ADBasher"
    success = validate_python_files(root)
    sys.exit(0 if success else 1)
