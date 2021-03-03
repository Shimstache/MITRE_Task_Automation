import pyattck
attack = pyattck.Attck()
myLogs = ["OAuth audit logs", "Authentication logs", "Office 365 audit logs"]
platform = ["Office 365"]
applicableTechs = []
allTechs = []
missingLogs = {}

def getPlatforms(platforms):
  platformTechniques = []
  for platform in platforms:
    for technique in attack.enterprise.techniques:
      if platform in technique.platforms:
        platformTechniques.append(technique)
        for subt in technique.subtechniques:
          if platform in subt.platforms:
            platformTechniques.append(subt)
  return(platformTechniques)

for technique in getPlatforms(platform):
  allTechs.append(technique)
  if technique.data_source:
    for ds in technique.data_source:
      if ds in myLogs:
        applicableTechs.append(technique)

allTechs=list(set(allTechs))
applicableTechs=list(set(applicableTechs))
      
print("Tactical Tasks")
print("*" * 30)
lines=[]
for technique in applicableTechs:
  # print("Monitor for adversary {} via {} ({}) ".format(technique.tactics[0].name, technique.name,technique.id))
  lines.append("Monitor for adversary {} in [{}] ({})".format(technique.name, ', '.join([t.name for t in technique.tactics]),technique.id))

lines=sorted(list(set(lines)))
print('\n'.join('TT 2.{} - {}'.format(x+1,lines[x]) for x in range(len(lines))))

print("\nNo logging source to identify following techniques")
print("*" * 30)
lines=[]
for technique in allTechs:
  if technique not in applicableTechs:
    # print("{} via {}".format(i.tactics[0].name,i.name))
    lines.append("{} in [{}] ({})".format(technique.name, ", ".join([t.name for t in technique.tactics]), technique.id))

    # Add to missing techs
    if technique.data_source:
      for ds in technique.data_source:
        missingLogs[ds] = missingLogs.get(ds,0) + 1
print('\n'.join(x for x in sorted(list(set(lines))))) 

print()
print("Missing Logs:")
print("*" * 30)
missingLogs=dict(sorted(missingLogs.items(), key=lambda item: item[1],reverse=True))
for log in missingLogs.keys():
  print("Insight into {} techniques by adding {}.".format(missingLogs[log],log)) 

print("\n" + "*" * 30)
print("Currently able to identify {:.2%} percent of Mitre Attack Matrix techniques with {} platforms".format(len(applicableTechs) / len(allTechs), platform))
print("*" * 30)

for tactic in sorted(attack.tactics,key=lambda i:i.id):
  try:
    allOfTactic = [t for t in allTechs if tactic.name in [n.name for n in t.tactics]]    
    applicableOfTactic = [t for t in applicableTechs if tactic.name in [n.name for n in t.tactics]]
    print("\t{:.2%} percent insight into {} tactic of above platforms.".format(len(applicableOfTactic)/len(allOfTactic),tactic.name))
  except:
    pass
