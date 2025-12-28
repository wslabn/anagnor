import yaml
from pathlib import Path
from typing import Any, Dict, List

class Config:
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.data = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            return {}
            
        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f) or {}
            
    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split('.')
        value = self.data
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
                
        return value
        
    def get_list(self, key: str, default: List = None) -> List:
        value = self.get(key, default or [])
        return value if isinstance(value, list) else [value]