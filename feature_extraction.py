#importing libraries
import re
import pandas as pd

### Features Extraction
#Feature 1 URL length
def long_url(str_in):
    l= len(str(str_in))
    if l < 75:
        return 0
    return 1
    
 
#Feature 2 @ symbol 
def have_at_symbol(str_in):
 
    if "@" in str(str_in):
        return 1
    return 0
    






#Feature 3 Redirecting using “//”
def redirection(str_in):
    if "//" in str(str_in):
        return 1
    return 0



#Feature 4 prefix and suffix
def dash_in_domain(str_in):
    if '-' in str(str_in):
        return 1
    return 0



#Feature 5 Sub-Domain and Multi Sub-Domains
def sub_domains(str_in):
    str_in=str(str_in)
    if str_in.count('.') >= 3:
        return 1
    else:
        return 0



#Feature 6 IP in URL
def ip_in_url(str_in):
    try:
        ipaddress.ip_address(str_in)
        return 1
    except:
        return 0



#Feature 7 Shortened URL
def shortening_service(str_in):
        """Tiny URL -> phishing otherwise legitimate"""
        match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',str_in)
        if match:
            return 1               # phishing
        else:
            return 0               # legitimate



#Feature 8 HTTPS in domain

def https_token(str_in):
    
    if 'http' in str(str_in):
        return 1
    else:
        return 0



from training import *
class feature_extractor:
    def __init__(self, url: str):
        self.input_url = url

    def extract(self):
        input_data = [{"URL": self.input_url}]
        temp_df = pd.DataFrame(input_data)

        protocol = temp_df['URL'].str.split("://", n=1, expand=True)

        # Extract the second column from the DataFrame
        protocol_col = protocol[1].astype(str)

        # Apply str.split() to the Pandas Series using a lambda function
        protocol_split = protocol_col.apply(lambda x: pd.Series(str(x).split("/", 1)))

        # Rename columns
        protocol_split.columns = ['domain_name', 'address']

        # Concatenate DataFrames
        splitted_data = pd.concat([protocol, protocol_split], axis=1)

        splitted_data['long_url'] = temp_df['URL'].apply(long_url)
        splitted_data['having_@_symbol'] = temp_df['URL'].apply(have_at_symbol)
        splitted_data['redirection_//_symbol'] = protocol_col.apply(redirection)
        splitted_data['prefix_suffix_separation'] = protocol_split['domain_name'].apply(dash_in_domain)
        splitted_data['sub_domains'] = splitted_data['domain_name'].apply(sub_domains)
        splitted_data['ip_in_url'] = splitted_data['domain_name'].apply(ip_in_url)
        splitted_data['shortened'] = temp_df['URL'].apply(shortening_service)
        splitted_data['https_token'] = protocol_col.apply(https_token)

        print(splitted_data)

        return predictor(splitted_data)


