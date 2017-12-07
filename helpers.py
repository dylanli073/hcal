
import os
import flask
import requests
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from apiclient import errors
import base64
from datetime import datetime
from time import mktime
import parsedatetime as pdt


# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope (separate for Gmail and Calendar APIs) allows for full modify/write
# access to the authenticated user's account and requires requests to use an SSL connection.
SCOPES_GMAIL = 'https://www.googleapis.com/auth/gmail.modify'
API_SERVICE_NAME_GMAIL = 'gmail'
API_VERSION_GMAIL = 'v1'

SCOPES_CAL = 'https://www.googleapis.com/auth/calendar'
API_SERVICE_NAME_CAL = 'calendar'
API_VERSION_CAL = 'v3'


# Parsing algorithm to search for instances of datetime in email message subjects and bodies
# If a datetime is found, add the event to Google calendar
def parseGmail():
  # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    # Build gmail and calendar instances
    gmail = googleapiclient.discovery.build(
        API_SERVICE_NAME_GMAIL, API_VERSION_GMAIL, credentials=credentials)
    cal = googleapiclient.discovery.build(
        API_SERVICE_NAME_CAL, API_VERSION_CAL, credentials=credentials)


    # Save credentials back to session in case access token was refreshed.
    flask.session['credentials'] = credentials_to_dict(credentials)

    # Create a parsedatetime instance
    pdtCal = pdt.Calendar()

    # Query all unread messages from Gmail inbox
    results = gmail.users().messages().list(userId='me', q='is:inbox', labelIds=['UNREAD']).execute()
    
    # If no messages were found, return empty list
    messages = results.get('messages', [])
    if not messages:
        continue
    else:
        # Search through messages for datetimes
        for message in messages:

            # Mark current message as READ so that it will not have to be checked for a datetime again
            gmail.users().messages().modify(userId='me', id=message['id'],
                                          body={'removeLabelIds': ['UNREAD']}).execute()

            # Obtain body of message in UTF-8 text after a decoding base64 string
            msg_body = GetMimeMessage(gmail, 'me', message['id']).lower()

            # Search for "subject" header of the message
            headers = GetMessage(gmail, 'me', message['id'])['payload']['headers']
            for header in headers:
                if header["name"].lower() == "subject":
                    subject = header["value"]
                    break

            # Ensure that message is not a reply (since the original email most likely contains the event and was already parsed)
            if "Re:" not in subject:

                # Search subject of email for datetime and convert from a time struct to a datetime object
                parsedDateSubject = pdtCal.parse(subject)[0]
                parsedDatetimeSubject = datetime.fromtimestamp(mktime(parsedDateSubject))

                # Convert parsed datetime and current datetime to number of seconds since epoch
                # (inspired by https://stackoverflow.com/questions/18269888/convert-datetime-format-into-seconds
                parsedDateSubjectInSeconds = int(mktime(parsedDateSubject))
                nowSubject = int(mktime(datetime.now().timetuple()))

                # If time parsed from email subject is different from current time
                # (i.e. more than 60 seconds away from current time), add event to calendar
                if int(abs(parsedDateSubjectInSeconds - nowSubject)) > 60:

                    # Create new event in calendar and store the parsed time
                    created_event = cal.events().quickAdd(calendarId='primary', text=parsedDatetimeSubject).execute()
                    
                    # Set name of newly created event to email subject and update event in calendar
                    created_event['summary'] = subject
                    cal.events().update(calendarId='primary', eventId=created_event['id'], body=created_event).execute()

                # If time parsed from email subject is within 60 seconds of current time, parse email body for a 
                # different, more accurete event time (if any)
                else:
                    # Search email body for datetime and convert from a time struct to a datetime object
                    parsedDateBody = pdtCal.parse(msg_body)[0]
                    parsedDatetimeBody = datetime.fromtimestamp(mktime(parsedDateBody))

                    # Search subject of email for datetime and convert from a time struct to a datetime object
                    parsedDateBodyInSeconds = int(mktime(parsedDateBody))
                    nowBody = int(mktime(datetime.now().timetuple()))

                    # If time parsed from email body is more than 60 seconds away from current time, add event to calendar
                    if int(abs(parsedDateBodyInSeconds - nowBody)) > 60:
                        created_event = cal.events().quickAdd(calendarId='primary', text=parsedDatetimeBody).execute()
                        created_event['summary'] = subject
                        cal.events().update(calendarId='primary', eventId=created_event['id'], body=created_event).execute()


# From Google API documentation
def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}


def GetMimeMessage(service, user_id, msg_id):
  """Get a Message and use it to create a MIME Message.

  Args:
    service: Authorized Gmail API service instance.
    user_id: User's email address. The special value "me"
    can be used to indicate the authenticated user.
    msg_id: The ID of the Message required.

  Returns:
    A MIME Message, consisting of data from Message.
  """
  # Use a series of try and except messages to find body of message and decode it from base64 and encode into UTF-8
  try:
      message = service.users().messages().get(userId=user_id, id=msg_id).execute()

      # Through analysis of sample emails, we determined that the "parts" key may have several similar nested values
      # that need to be checked for body text
      try:
          msg_part = message['payload']['parts'][0]
          try:
              msg_str = str(base64.urlsafe_b64decode(msg_part['body']['data'].encode('UTF-8')))
          except KeyError:
              msg_str = str(base64.urlsafe_b64decode(msg_part['parts'][0]['body']['data'].encode('UTF-8')))
      except KeyError:
          msg_part = message['payload']['body']
          try:
              msg_str = str(base64.urlsafe_b64decode(msg_part['data'].encode('UTF-8')))
          except KeyError:
              msg_str = ""

      return msg_str
      
  except errors.HttpError as error:
      print('An error occurred: %s' % error)
      return ""


def GetMessage(service, user_id, msg_id):
    """Get a Message with given ID.

    Args:
      service: Authorized Gmail API service instance.
      user_id: User's email address. The special value "me"
      can be used to indicate the authenticated user.
      msg_id: The ID of the Message required.

    Returns:
      A Message.
    """
    try:
        message = service.users().messages().get(userId=user_id, id=msg_id).execute()
        return message
    except errors.HttpError as error:
        print('An error occurred: %s' % error)
        return ""


# Returns list of lists of Google Calendar events (name and id)
# Adapted from Google Calendar API documentation
def listEvents(service):
    retCalList = []
    page_token = None
    while True:
        calendar_list = service.calendarList().list(pageToken=page_token).execute()
        for calendar_list_entry in calendar_list['items']:
            retCalList.append([calendar_list_entry['summary'], calendar_list_entry['id']])
        page_token = calendar_list.get('nextPageToken')
        if not page_token:
            break
    return retCalList

