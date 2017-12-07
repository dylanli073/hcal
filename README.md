# hcal #
CS50 Final Project - Vincent Li, Anna Lou, Dylan Li

HCAL is a web application, hosted at http://hcal50.herokuapp.com, for compiling and visualizing upcoming club events extracted from organization mailing lists. Emails are first scraped for details about subjects, dates, and times and entered into a list of calendars, after which users are able to enter a combination of queries to find the events they have in mind or to explore for upcoming events. No more digging through an avalanche of emails!  

On the web application, the event calendar updates at “/”. New emails are gathered from a Gmail (not the user’s!) that is subscribed to a number of mailing lists. The calendar will update in its current view and filter, displaying the new events announced in these recent emails. By selecting different views and filters or entering queries into the search bar, the user is then able to visualize upcoming events efficiently rather than digging through a mound of organizations and events they are not interested in. Clicking on an event will prompt a popup to offer more details on the event or to suggest copying the event to the user’s personal calendar.  

When the user copies the event to their personal calendar, they are able to visualize and receive reminders about the event and its details without having to hunt for the specific email or clutter their calendar with automatic Gmail events. Even with imperfect estimates, users are able to easily browse through possible events for something that might catch their eye, or they might even be reminded of a deadline they hadn’t noticed because of the influx of emails.  


## Note ##
At this stage in our project development, we have not gotten the opportunity to experiment with different authentication accounts. So in order to run our program, you must log in via our admin user account (0dylan7li3@gmail.com) and authenticate through Google. Then visit the URL's "/authorize-gmail" and "/authorize-cal" to authorize the Gmail and Google Calendar APIs. Then visit the home page ("/") to get started!  
  
## Note 2 ##
Our web application deployed on Heroku may experience some occasional internal server errors, which do not occur when running the Flask app locally. We hope to resolve this issue sometime in the near future.