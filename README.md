# Automate The Standup - An AI Agent That Shares Things You're Working On With Your Team

Why

- It's ineficient and impracitcal to share all things you're up to with all your colleagues
- Asking questions to everyone in group chats takes lots of time because it consumes the writers time plus the time of every reader
- As a result, people either:
  - end up working with incomplete context because questions are too expensive to ask
  - or end up asking and answering questions to multiple people, inflating meeting and communication time
- We need a way to decrease meeting and communication time, making employees more efficient

Required features

- ✅ Track all URLs you visit
- Get markdown variant for all accessible pages. see status code incase not ok
- Have a clearer understanding of what urls aren't readable (due to privacy reasons or hard html)
- Creates a private `llms.txt` directory for your web browsing activity, creating a very clear understanding of what you're doing
- A pricing and group system to invite colleagues
- IDP for non-public websites like github, notion, and x
- An MCP with tools to search and navigate the history directory
- Add LLM assessment to not share certain websites based on title/url/description
- Every night, create an AI-generated summary of what you're up to

Limitations compared to pipedream

- doesn't track other programs except chrome
- doesn't capture important sites like slack, notion, email, or other communication apps unless we create

How does this differentiate from https://screenpi.pe?

- isnt privacy focussed, rather, it's focused on better context & collaboration within company
- the format of what IS captured is more crisp, contains the whole page content + time on site
- the installation is smoother: just install a chrome extension and login with your x account

How does this differentiate from https://macroscope.com?

- broader understanding of what someone is up to, beyond just code
