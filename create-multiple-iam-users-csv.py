import boto3
import csv
from csv import reader
from pprint import pprint
from random import choice
import secrets
import string
import sys

def get_iam_client_object():
    session=boto3.session.Session(profile_name="boto3")
    iam_client=session.client(service_name="iam")
    return iam_client

def get_random_password():

    letters = string.ascii_letters
    digits = string.digits
    special_chars = string.punctuation
    alphabet = letters + digits + special_chars
    pwd_length = 12

    while True:
        pwd = ''
        for i in range(pwd_length):
            pwd += ''.join(secrets.choice(alphabet))

        if (any(char in special_chars for char in pwd) and 
            sum(char in digits for char in pwd)>=2):
                break
    #print(pwd)
    return pwd



def read_csv():

    csv_data =[];
    with open('iam_users.csv', 'r') as read_obj:
        csv_reader = reader(read_obj)
        header = next(csv_reader)
        if header != None:    
            for row in csv_reader:
            # row variable is a list that represents a row in csv
                #print(row)
                #return row
                csv_data.append(row)
                #print("Username is: {}, PolicyARN is: {}, Programatic Access {}, Console Access {}".format((row[1]),(row[4]),(row[2]),(row[3])))
              
    return csv_data

 
def main():

    iam_client=get_iam_client_object()
    #password=get_random_password()
    #print (password)
    csv_data=read_csv();
    
    for each_item in csv_data:
        #print(each_item[1])
        password=get_random_password()

        try:

            iam_client.create_user(UserName=(each_item[1]))
            
        except  Exception as e:
            if e.response['Error']['Code'] =="EntityAlreadyExists":
                print ("Already IAM user with name {} exists".format(each_item[1]))
                sys.exit(0)
            else:
                print ("Please verify the following error and retry")
                print (e)
                sys.exit(1)
        iam_client.attach_user_policy(UserName=(each_item[1]),PolicyArn=(each_item[4]))

        

        if (each_item[2])=="Yes":
            print("User: {} needs programatic access".format((each_item[1])))
            #iam_client.create_user(UserName=(each_item[1]))
            response=iam_client.create_access_key(UserName=(each_item[1]))
            #iam_client.attach_user_policy(UserName=(each_item[1]),PolicyArn=(each_item[4]))
            print("IAM UserName={}, AccesKeyID={}, SecretKey={}".format((each_item[1]),(response['AccessKey']['AccessKeyId']),(response['AccessKey']['SecretAccessKey'])))
            
            if (each_item[3])=="Yes":
                print("User: {} needs console access also".format((each_item[1])))
                #iam_client.create_user(UserName=(each_item[1]))
                iam_client.create_login_profile(UserName=(each_item[1]),Password=password,PasswordResetRequired=False)
                #iam_client.attach_user_policy(UserName=(each_item[1]),PolicyArn=(each_item[4]))
                print("IAM UserName={} and Password={}".format((each_item[1]), password))

            else:
                print("User: {} doesn't need console access".format((each_item[1])))

                
        else:
            print("User: {} doesn't need Programatic access".format((each_item[1])))

            if (each_item[3])=="Yes":
                print("User: {} needs console access only".format((each_item[1])))
                #iam_client.create_user(UserName=(each_item[1]))
                iam_client.create_login_profile(UserName=(each_item[1]),Password=password,PasswordResetRequired=False)
                #iam_client.attach_user_policy(UserName=(each_item[1]),PolicyArn=(each_item[4]))
                print("IAM UserName={} and Password={}".format((each_item[1]), password))
            else:
                print("User: {} doesn't need console access also".format((each_item[1])))

        print("===================================================================================================================")
        

if __name__ == "__main__":
    main()