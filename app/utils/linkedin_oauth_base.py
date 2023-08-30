# from config import config
#
#
# class LinkedinSvc:
#     # consumer_key = config.LINKEDIN_CLIENT_ID
#     # consumer_secret = config.LINKEDIN_CLIENT_SECRET
#     #
#     # request_token_params = {
#     #     'scope': 'openid,profile,email,w_member_social'
#     # }
#     # base_url = 'https://api.linkedin.com/v2/'
#     # request_token_url = None
#     # access_token_method = 'POST'
#     # access_token_url = 'https://www.linkedin.com/oauth/v2/accessToken'
#     # authorize_url = 'https://www.linkedin.com/oauth/v2/authorization'
#
#     linkedin_con = None
#
#     def __init__(self, oauth):
#         self.linkedin_con = None
#         self.oauth = oauth
#         self.consumer_key = config.LINKEDIN_CLIENT_ID
#         self.consumer_secret = config.LINKEDIN_CLIENT_SECRET
#
#         self.request_token_params = {
#             'scope': 'openid,profile,email,w_member_social'
#         }
#         self.base_url = 'https://api.linkedin.com/v2/'
#         self.request_token_url = None
#         self.access_token_method = 'POST'
#         self.access_token_url = 'https://www.linkedin.com/oauth/v2/accessToken'
#         self.authorize_url = 'https://www.linkedin.com/oauth/v2/authorization'
#
#     def initialize(self):
#         self.linkedin_con = self.oauth.remote_app(
#
#             name='linkedin_oauth',
#             consumer_key=self.consumer_key,
#             consumer_secret=self.consumer_secret,
#             request_token_params=self.request_token_params,
#             base_url=self.base_url,
#             request_token_url=self.request_token_url,
#             access_token_method=self.access_token_method,
#             access_token_url=self.access_token_url,
#             authorize_url=self.authorize_url,
#         )
#
#     @staticmethod
#     def linkedin():
#         return LinkedinSvc.linkedin_con
