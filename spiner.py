import time
import sys

def spinning_cursor(cursor_progress):
    """Create a spinning cursor animation"""
    cursors = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    sys.stdout.write(cursors[cursor_progress])
    sys.stdout.flush()
    sys.stdout.write('\b')