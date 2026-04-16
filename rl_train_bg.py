import sys
sys.path.insert(0, '/home/kali/osints')
from sentinel_brain.rl_agent import RLAgent
from sentinel_brain.kali_controller import KaliController

agent = RLAgent()
kali  = KaliController()
agent.train(
    targets=['neurodev.netlify.app', 'learnshadowcode.netlify.app', 'downloadanything.jo3.org'],
    kali=kali,
    episodes=200
)
print("Training complete!")
