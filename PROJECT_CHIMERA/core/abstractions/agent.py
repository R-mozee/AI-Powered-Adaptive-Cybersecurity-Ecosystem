# core/abstractions/agent.py
from abc import ABC, abstractmethod

class BaseAgent(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def run(self): pass

    @abstractmethod
    def cycle(self): pass

    @abstractmethod
    def shutdown(self): pass