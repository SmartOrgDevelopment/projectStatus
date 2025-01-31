import logging
import traceback
import requests

import urllib3

logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



def request_call(method: str, url:str, headers: dict, json: dict, timeout: int, verify: bool):
    try:
        response = requests.request(
            method, url, json=json, headers=headers, timeout=timeout, verify=verify
        )
        response.raise_for_status()
       
    except requests.exceptions.HTTPError as errh: 
        # print("HTTP Error") 
        # print(errh.args[0]) 
        logging.error('HTTTP Error:\n  %s\n', errh.args[0])
        logging.error(f'\n{method}: {url}\n')
        return None
    except requests.exceptions.ReadTimeout as errrt: 
        logging.error('Time-Out Error:  %s', errrt.args[0])
        logging.error(f'\n{method}: {url}\n')
        return None
    except requests.exceptions.ConnectionError as conerr: 
        logging.error('Connection Error:\n  %s\n', conerr.args[0])
        logging.error(f'\n{method}: {url}\n')
        return None
    except requests.exceptions.RequestException as errex: 
        logging.error('Exception Request Error:  %s', errex.args[0])
        logging.error(f'\n{method}: {url}\n')
        return None
    else:
         if response:
            return response
         else:
             return None


# def requests_call(method: str, url: str, headers: dict, json: dict, timeout: int, verify: bool):
#     '''A function to wrap pythn requests calls with exception checkinng

#     '''
#     # see the docs: if you set no timeout the call never times out! A tuple means "max 
#     # connect time" and "max read time"
    
#     try:
#         response = requests.request(method, url, headers=headers, json=json, timeout=timeout, verify=verify)
#         response.raise_for_status()

#     except requests.exceptions.HTTPError as errh: 
#             # print("HTTP Error") 
#             # print(errh.args[0]) 
#             logging.error('HTTTP Error:\n  %s\n', errh.args[0])
#             print()
#             print(errh.args)
#             print()
#             return None
#     except requests.exceptions.ReadTimeout as errrt: 
#         logging.error('Time-Out Error:  %s', errrt.args[0])
#         return (False, errrt, None)
#     except requests.exceptions.ConnectionError as conerr: 
#         logging.error('Connection Error:\n  %s\n', conerr.args[0])
#         return (False, conerr, None)
#     except requests.exceptions.RequestException as errex: 
#         logging.error('Exception Request Error:  %s', errex.args[0])
#         return (False, errex, None)
#     else:
#         return (True, response.json()['data'],response.json()['token'])
