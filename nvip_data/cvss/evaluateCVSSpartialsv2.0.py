# Peter Mell, National Institute of Standards and Technology
# License: public domain (attribution is requested, as appropriate)
# 2021-2-10

# See the associated README file for information on using this

import pickle
 
path="./"

def import_vectors(suffix='tCVE',verbose=False):
    fname=path+'CVE-CWE-CVSS-Vectors-v3-'+suffix+'.pickle'
    #if verbose: print('evaluateCVSSpartials.py is opening pickle file',fname)
    with open(fname, 'rb') as f:
        v3Vectors=pickle.load(f)
    #print(v3Vectors[0])
    return(v3Vectors)  

def match(partial,vector):
    assert(len(partial)==8)
    assert(len(vector)==16)
    match=True
    for x in range(8):
        #print(x,end=" ")
        p=partial[x]
        v=vector[x+8]
        if p!=v and p!='X' and not (p=='LH' and (v=='L' or v=='H')): 
            match=False
            break
    #print("\n")
    return match
  
def get_cvss_for_partial(partial):
    matchscores=[]
    for vec in v3Vectors:
        if match(partial,vec):
            matchscores.append(vec[5])
    return(matchscores)

###############################################################################
# The following two functions are for importing a file of partial vectors

def eval_partial(partial,verbose=True):
    if verbose: print(partial)
    matchscores=[]
    for vec in v3Vectors:
        if match(partial,vec):
            matchscores.append(vec[5])
            print("match",partial,vec[8:])

    #if len(matchscores)==0: return [-1,-1,-1,-1]
    if len(matchscores)==0: return [-1,-1,-1]
        
    minscore=min(matchscores)
    maxscore=max(matchscores)
    meanscore=sum(matchscores)/len(matchscores)
    #meanscore=statistics.mean(matchscores)
     
    #sd=statistics.stdev(matchscores) # stdev is for having a sample of a population
    #sd=statistics.pstdev(matchscores) # pstdev is for having the entire population

    #return [float(meanscore),float(minscore),float(maxscore),float(sd)] # float in Python is a Java double
    
    return [float(meanscore),float(minscore),float(maxscore)] # float in Python is a Java double

def import_partials():
    fname=path+'CVSSpartials.csv'
    #print('opening CVSS partials file',fname,flush=True)
    with open(fname, 'r') as f:
        partials=f.readlines()
    for x in range(len(partials)):
        partials[x]=partials[x].split(",")
        partials[x][7]=partials[x][7][:1]
        #print("x:",partials[x])
    return(partials)  
   
def process_partial_file():
    partials=import_partials()
    
    fname=path+"CVSS-statistics-output.csv"
    f=open(fname,"w")
    
    #header_string="AV, AC, PR, UI, S, C, I, A, meanCVSS, minCVSS, maxCVSS, standard_dev\n"
    header_string="AV, AC, PR, UI, S, C, I, A, meanCVSS, minCVSS, maxCVSS\n"
    f.write(header_string)
    
    output_strings=[]
    for p in partials:
        meanscore,minscore,maxscore=eval_partial(p)
        #sd=statistics.pstdev(matchscores) # pstdev is for having the entire population
        output_string=p[0]+", "+p[1]+", "+p[2]+", "+p[3]+", "+p[4]+", "+p[5]+", "+p[6]+", "+p[7]+", "
        #output_string+=str(meanscore)+", "+str(minscore)+", "+str(maxscore)+", "+str(sd)+"\n"
        output_string+=str(meanscore)+", "+str(minscore)+", "+str(maxscore)+"\n"
        output_strings.append(output_string)
        #print(output_string)
    #print(output_strings)
    #print("writing output file ",fname)
    f.writelines(output_strings) 
    f.close()

v3Vectors=import_vectors() # this imports the CVSS vectors to support evaluating partial CVSS vectors   
#process_partial_file()
    


