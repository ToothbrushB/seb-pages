import uuid, secrets
from datetime import datetime

WORD_LIST = [
    'alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel',
    'india', 'juliet', 'kilo', 'lima', 'mike', 'november', 'oscar', 'papa',
    'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor', 'whiskey', 'xray',
    'yankee', 'zulu', 'azure', 'bronze', 'coral', 'diamond', 'emerald', 'forest',
    'granite', 'harmony', 'ivory', 'jade', 'knight', 'lunar', 'marble', 'nebula',
    'ocean', 'phoenix', 'quartz', 'ruby', 'sapphire', 'tiger', 'unicorn', 'violet',
    'wizard', 'xenon', 'yellow', 'zenith', 'arctic', 'blaze', 'cosmic', 'dragon',
    'eagle', 'flame', 'galaxy', 'hawk', 'inferno', 'jaguar', 'kraken', 'lynx',
    'meteor', 'nova', 'orbit', 'prism', 'quantum', 'raven', 'solar', 'thunder',
    'ultra', 'vortex', 'wolf', 'xeno', 'yeti', 'zodiac', 'atom', 'bolt',
    'cipher', 'drift', 'ember', 'flux', 'glow', 'haze', 'ion', 'jolt',
    'kinetic', 'laser', 'matrix', 'nexus', 'omega', 'pulse', 'quasar', 'radar',
    'spectrum', 'titan', 'unity', 'vertex', 'wave', 'xenith', 'yield', 'zero'
]

def generate_exam_id():
    return str(uuid.uuid4())

def generate_exam_key():
    words = [secrets.choice(WORD_LIST) for _ in range(4)]
    return '-'.join(words).upper()

def exam_id_exists(exam_id, EXAMS):
    return exam_id in EXAMS

def exam_key_exists(exam_key, EXAMS):
    return any(exam.get('exam_key') == exam_key for exam in EXAMS.values())
