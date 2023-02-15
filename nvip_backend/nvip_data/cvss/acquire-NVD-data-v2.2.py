# Peter Mell, National Institute of Standards and Technology
# License: public domain (attribution is requested, as appropriate)
# 2021-2-10

# This program processes the CVE analysis .json.gz data files from NVD 
# to extract CVSS vector information / CWE information and encode this in pickle files.
# These input data files are available at https://nvd.nist.gov/vuln/data-feeds

# Output File Descriptions

# Filename: CVSS-Vectors-V2-[suffix].pickle, Datastructure Name: v2Vectors
# Description: list of vectors for all CVEs for which we have a v2 vector from NVD
# Vector format: CVE, publication date, yearChange boolean, [list of CWEs], CVSS version, baseScore, exploitabilityScore, impactScore, AV, AC, Au, C, I, and A, 

# Filename: CVSS-Vectors-V3-[suffix].pickle, Datastructure Name: v3Vectors
# Description: list of vectors for all CVEs for which we have a v3 vector from NVD
# Vector format: CVE, publication date, yearChange boolean, [list of CWEs], CVSS version, baseScore, exploitabilityScore, impactScore, AV, AC, PR, UI, S, C, I, and A

# Filename: noCWECVSSv2Vectors-[suffix].pickle (only if activated at bottom of this program)
# Description: list of vectors for all CVEs for which there is no CWE mapped (but for which we do have CVSS v2 scoring)
# Vector format: CVE, publication date, yearChange boolean, [list of CWEs], CVSS version, baseScore, exploitabilityScore, impactScore, AV, AC, Au, C, I, and A, 

# Filename: noCWECVSSv3Vectors-[suffix].pickle (only if activated at bottom of this program)
# Description: list of vectors for all CVEs for which there is no CWE mapped (but for which we do have CVSS v3 scoring)
# Vector format: CVE, publication date, yearChange boolean, [list of CWEs], CVSS version, baseScore, exploitabilityScore, impactScore, AV, AC, PR, UI, S, C, I, and A

# Each filename above has a suffix prior to the '.pickle'. The suffix describes how
# the publication dates were calculated for each CVE. The options are 'tCVE' where the
# year from the CVE name is used, 'tNVD' where the NVD publish date is used, and
# 'tNVDCVE' where the NVD publish date is used except that the CVE year is used if
# prior to the NVD publish date year.

# The yearChange boolean is 1 if the NVD publication date was replaced with an earlier year from the CVE name
# This is only used when the suffix is 'tNVDCVE', otherwise it is always set to 0.

# Assane: the data we have been using up to this point is in the 'tNVDCVE' suffix files (my favorite)

# Note, users should configure the following variables below:
# path, years, useCVEYear, and useNVDandCVEDates

# Example output:
#['CVE-2020-0097', '2020-05-14', 0, [269], 3, 7.8, 1.8, 5.9, 'L', 'L', 'L', 'N', 'U', 'H', 'H', 'H']
#['CVE-2020-0098', '2020-05-14', 0, [269], 3, 7.8, 1.8, 5.9, 'L', 'L', 'L', 'N', 'U', 'H', 'H', 'H']
#['CVE-2020-0099', '2020-12-14', 0, [269], 3, 7.8, 1.8, 5.9, 'L', 'L', 'N', 'R', 'U', 'H', 'H', 'H']
#['CVE-2020-0100', '2020-05-14', 0, [125], 3, 5.5, 1.8, 3.6, 'L', 'L', 'L', 'N', 'U', 'H', 'N', 'N']
#['CVE-2020-0101', '2020-05-14', 0, [200], 3, 5.5, 1.8, 3.6, 'L', 'L', 'L', 'N', 'U', 'H', 'N', 'N']
#['CVE-2020-0102', '2020-05-14', 0, [787], 3, 7.8, 1.8, 5.9, 'L', 'L', 'L', 'N', 'U', 'H', 'H', 'H']
#['CVE-2020-0103', '2020-05-14', 0, [119], 3, 9.8, 3.9, 5.9, 'N', 'L', 'N', 'N', 'U', 'H', 'H', 'H']
#['CVE-2020-0104', '2020-05-14', 0, [200], 3, 5.5, 1.8, 3.6, 'L', 'L', 'L', 'N', 'U', 'H', 'N', 'N']

import json
import gzip
import pickle
import requests
from os import remove

#************************ USER MAY CONFIGURE THIS
path='./' # this is where the final output files are stored and tmp files generated and then deleted

#************************ USER MAY CONFIGURE THIS
years=[str(year) for year in range(2020,2021)]
years=["2020"]
years.reverse()

testing=False
if testing: years=['2020']

#************************ USER SHOULD CONFIGURE THIS
# the default is to use the publication date from NVD
useCVEYear=True # this makes the publish date the year specified in the CVE name
useNVDandCVEDates=True # this makes the publish date the CVE year if that is earlier than the NVD publish date
if useCVEYear:
    useNVDandCVEDates=False

if useCVEYear:
    print('Determining CVE publicate dates by the year in the CVE name')
else:
    print('Determining CVE publication dates by the NVD publication date')
if useNVDandCVEDates:
    print('  (but using CVE name year if prior to year in NVD publication date)')

v2Vectors=[]
v3Vectors=[]
noCWECVSSv2Vectors=[]
noCWECVSSv3Vectors=[]
yearChangeCountTotal=0 # See note below on year labels

for year in years:
    try:
#        url='https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-'+year+'.json.gz'
        url='https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-'+year+'.json.gz'        
        resp = requests.get(url) # creating HTTP response object from given url 
        filename='nvdcve-1.1-'+year+'.json.gz'
        with open(path+filename, 'wb') as f:  
            f.write(resp.content)
        with gzip.GzipFile(path+filename, 'r') as fin:
            cve_dict = json.loads(fin.read().decode('utf-8'))
        remove(path+filename)
    except:
        print('Datafile for year',year,'not found')
        remove(path+filename)
        continue

    #print(cve_dict.keys())

    nCVSS=0
    nCVSSv2=0
    nCVSSv3=0
    nCWEnoinfo=0
    nCWEother=0

    yearChangeCount=0 # count of CVEs for which the CVE label year is earlier than the publication date
    
    for rec in cve_dict['CVE_Items']:   
        CVE=rec['cve']['CVE_data_meta']['ID']
        CVEYear=int(CVE.split('-')[1])
        publishedDate=rec['publishedDate'].split('T')[0]
        publishedYear=int(publishedDate.split('-')[0])
        yearChange=False
        if useNVDandCVEDates:
            if publishedYear>CVEYear:
                publishedDate=str(CVEYear)+'-12-31'
                yearChangeCount=yearChangeCount+1
                yearChangeCountTotal=yearChangeCountTotal+1
                yearChange=True
            # NOTE: Some vulns were added years after they were discovered. They have a CVE name year that is correct
            # and a publishDate which is when they analyzed the vulnerability, not when it was discovered
            # For these we change the date to be Dec 31 of the year mentioned in the CVE name year.
        if useCVEYear:
            publishedDate=str(CVEYear)+'-12-31'
        
        #print("\n",CVE,rec['cve']['problemtype']['problemtype_data'][0]['description'],"\n")
        CWEList=[]
        CWEnoinfo=False
        CWEother=False
        for data in rec['cve']['problemtype']['problemtype_data']:
            for entry in data['description']:
                if entry['value']=='NVD-CWE-noinfo':# and entry['value']!='NVD-CWE-Other':
                    CWEnoinfo=True
                elif entry['value']=='NVD-CWE-Other':
                    CWEother=True
                    CWEList.append(0)
                else:
                    CWE=int(entry['value'].split('-')[1])
                    CWEList.append(CWE)
        if CWEother==True: # correct for analyst error
            CWEnoinfo=False
#        if CWEother==True and len(CWEList)>1: # correct for analyst error
#                CWEother=False
        if CWEnoinfo==True and len(CWEList)>0: # correct for analyst error
                CWEnoinfo=False
            
        vecBase=[]    
        vecBase.insert(0,CVE)
        vecBase.insert(1,publishedDate)
        vecBase.insert(2,int(yearChange))
        vecBase.insert(3,CWEList)
                    
        newVec2=[] # CVSSv2, this is the vector information that we will store, not the official CVSS vector
        newVec3=[] # CVSSv3
        hasCVSS=False

#        if CVE=='CVE-2019-8136':
#            print(rec['impact'])
        
        # Process V2 Scores            
        if ('baseMetricV2' in rec['impact']): 
            hasCVSS=True
            nCVSSv2+=1
            vecV2=rec['impact']['baseMetricV2']['cvssV2']['vectorString'] # official CVSS v2 vector
            #print(vecV2)
            elementsV2=vecV2.split('/')
            CVSSAttributes=[]
            for elem in elementsV2:
                CVSSAttributes=CVSSAttributes+[elem.split(':')[1]] # grabs the element values (e.g., C:H becomes simply H)            
            newVec2=vecBase+[2]+[rec['impact']['baseMetricV2']['cvssV2']['baseScore']] + [rec['impact']['baseMetricV2']['exploitabilityScore']] + [rec['impact']['baseMetricV2']['impactScore']]+CVSSAttributes
            v2Vectors=v2Vectors+[newVec2]
#            if CVE=='CVE-2019-8136':
#                print("\n",newVec2)
                
        # Process V3 Scores
        if ('baseMetricV3' in rec['impact']): 
            hasCVSS=True
            nCVSSv3+=1
            vecV3=rec['impact']['baseMetricV3']['cvssV3']['vectorString'] # official CVSS v3 vector
            #print(vecV3)
            elementsV3=vecV3.split('/')
            CVSSAttributes=[]
            for elem in elementsV3:
                CVSSAttributes=CVSSAttributes+[elem.split(':')[1]] # grabs the element values (e.g., C:H becomes simply H)            
            newVec3=vecBase+[3]+[rec['impact']['baseMetricV3']['cvssV3']['baseScore']] + [rec['impact']['baseMetricV3']['exploitabilityScore']] + [rec['impact']['baseMetricV3']['impactScore']]+CVSSAttributes[1:]
            v3Vectors=v3Vectors+[newVec3]     
#            if CVE=='CVE-2019-8136':
#                print("\n",newVec3)
            #if len(CWEList)>1:
            #    print(newVec3)

        if hasCVSS: # only want to count this if CVE was analyzed
            nCVSS+=1
            if CWEnoinfo==True or CWEother==True:
                if newVec3!=[]:
                    noCWECVSSv3Vectors=noCWECVSSv3Vectors+[newVec3]
                    #print(newVec3)
                if CWEnoinfo==True:
                    nCWEnoinfo+=1
                if CWEother==True and len(CWEList)==1:
                    nCWEother+=1
                if newVec2!=[]:
                    noCWECVSSv2Vectors=noCWECVSSv2Vectors+[newVec2]
                    #print(newVec2)
                #print(CWEList)
                
    print("\n(",len(cve_dict['CVE_Items']),"CVEcount,",nCVSS,"nCVSS,",len(cve_dict['CVE_Items'])-nCVSS,"no CVSS/CWE)",filename)
    print("(",nCVSSv2,"CVSS v2,",nCVSSv3,"CVSS v3,",nCWEnoinfo,"CWEnoinfo,",nCWEother,"CWEother)")
    print("yearChangeCount",yearChangeCount)
    
print("\nFinal Statistics,",len(v2Vectors),"v2Vectors",len(v3Vectors),"v3Vectors")
print("yearChangeCountTotal",yearChangeCountTotal)

vectors=[]
for x in range(len(v3Vectors)):
    if v3Vectors[x][5]==0:
        print(v3Vectors[x])
#    vector=v3Vectors[x][8:]
#    if vector[4]=='C' and vector[5]=='H' and vector[6]!='L' and vector[7]!='L':
#        vectors.append(tuple(vector))
#3vectors=set(vectors)
#for v in vectors:
#  print(v)

# This modifies the output files to indicate how the publish date was calculated for each CVE
if useCVEYear==True:
    fileModifier='-tCVE'
if useNVDandCVEDates==True:
    fileModifier='-tNVDCVE'
if useNVDandCVEDates==False and useCVEYear==False:
    fileModifier='-tNVD'
    
if not testing:
    #print('pickling',flush=True)
    #fname=path+'CVE-CWE-CVSS-Vectors-v2'+fileModifier+'.pickle'      
    #print(fname,flush=True)
    #with open(fname, 'wb') as f:
    #    pickle.dump(v2Vectors, f, pickle.HIGHEST_PROTOCOL)  
        
    fname=path+'CVE-CWE-CVSS-Vectors-v3'+fileModifier+years[0]+"-"+years[-1]+'.pickle'
    print(fname,flush=True)
    with open(fname, 'wb') as f:
        pickle.dump(v3Vectors, f, protocol=2)
