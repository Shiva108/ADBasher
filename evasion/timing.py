#!/usr/bin/env python3
"""
Timing evasion module for ADBasher.
Implements jitter and business hours restrictions based on config.yaml
"""
import time
import random
from datetime import datetime

class TimingEvasion:
    def __init__(self, config):
        self.evasion_config = config.get('evasion', {})
        self.jitter_min = self.evasion_config.get('jitter_min', 5)
        self.jitter_max = self.evasion_config.get('jitter_max', 30)
        self.work_hours_only = self.evasion_config.get('work_hours_only', False)
        self.mode = self.evasion_config.get('mode', 'standard')
    
    def apply_jitter(self):
        """Sleep for a random duration based on jitter settings."""
        # Adjust jitter based on mode
        if self.mode == 'stealth':
            jitter_min = self.jitter_min * 2
            jitter_max = self.jitter_max * 3
        elif self.mode == 'aggressive':
            jitter_min = max(1, self.jitter_min // 2)
            jitter_max = max(5, self.jitter_max // 2)
        else:  # standard
            jitter_min = self.jitter_min
            jitter_max = self.jitter_max
        
        sleep_duration = random.randint(jitter_min, jitter_max)
        time.sleep(sleep_duration)
        return sleep_duration
    
    def check_business_hours(self):
        """Check if current time is within business hours (9 AM - 5 PM)."""
        if not self.work_hours_only:
            return True
        
        current_hour = datetime.now().hour
        return 9 <= current_hour < 17
    
    def wait_for_business_hours(self):
        """Wait until business hours if work_hours_only is enabled."""
        while not self.check_business_hours():
            print(f"[Evasion] Outside business hours. Pausing until 9 AM...")
            time.sleep(3600)  # Wait 1 hour
