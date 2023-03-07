README - CVSS Score Estimator

Author: Peter Mell, National Institute of Standards and Technology
License: Public domain (attribution is desired, as appropriate)

The python program 'acquire-NVD-data-v2.1.py' downloads all CVE vulnerabilities from the NVD
website with a publish data in the year 2020. It writes this data to the file
'CVE-CWE-CVSS-Vectors-v3-tNVDCVE.pickle' using a Python proprietary format (for speed). 
If the output file already exists, there is no need to run this program. If it is run,
the output will change as NVD regularly analyzes and publishes vulnerabilities from prior years.

The python program 'evaluateCVSSpartials.py' enables a user to specify partial CVSS vectors. The program then
uses CVSS statistics from the year 2020 to determine the mean, min, max, and standard deviation 
for all published NVD CVE vulneabilities that match the partial vector. This enables one to estimate
CVSS scores for partial vectors and to determine the likely degree of accuracy for any such generated
estimates. Note that this program automatically reads in 'CVE-CWE-CVSS-Vectors-v3-tNVDCVE.pickle' in 
order to operate. If this datafile is not placed in the same directory as 'evaluateCVSSpartials.py',
the path specified at the top of the file needs to be updated.

It operates in two modes: 1) file import and export and 2) interactive. The former is used to 
process a large number of partial CVSS vectors in a batch. The latter is to process a single
vector at a time on demand. 

** Instructions for File Import and Export

The input file 'CVSSpartials.csv' must have the same format as the example file placed there.
It will have a row per CVSS vector to be represented. There will be 8 columns representing the
8 CVSS v3.1 metrics. The letter abbreviations for the metric values to be used aligns with the 
CVSS v3.1 specification. To denote that a particular metric value is not specified in the input, 
use the letter 'X'.

The python program 'evaluateCVSSpartials.py' reads in the input file 'CVSSpartials.csv' from the same 
directory and then outputs a file 'CVSS-statistics-output.csv'. The first line of the output file describes the 
contents of each column (shown below). 

Output columns: AV, AC, PR, UI, S, C, I, A, meanCVSS, minCVSS, maxCVSS, standard_dev

To use the file import/export mode either uncomment the last line in 'evaluateCVSSpartials.py' and then execute
the Python code or integrate the code into some other program and call the function
'process_partial_file()'. 

** Instructions for Interactive Use

Integrate the program 'evaluateCVSSpartials.py' into the program that will be supplying the 
CVSS partial vectors. Then simply call the function 'eval_partial(partial)' as desired with a particular 
partial vector. The parameter 'partial' must be an array of strings, each consisting of a single letter 
cooresponding to the letter abbreviations for the metric values in the CVSS v3.1 specification 
(in the order they are presented therein: AV, AC, PR, UI, S, C, I, and A). To denote a particular metric 
values as not specified, use an 'X'. Example valid partial parameters are shown in the rows of the test 
input file 'CVSSpartials.csv'.

The output will be an array of four Python floats (equivalent to double in Java) indicating the 
following values: meanCVSS, minCVSS, maxCVSS, standard_dev. 

There also exists another function that can be used interactively. The function 'get_cvss_for_partial(partial)'
returns an array containing all CVSS values that coorespond to the supplied partial for CVEs published
by NVD in the year 2020. This can be used to perform statistical research on the applicable CVSS score
distribution.



