
# Avoid undesired users accessing your REST API using JWT.

## WHY and WHEN you should use JWT:

When two systems exchange data, using a JSON Web Token is a great way to identify the user without sending private credentials on every request but creating the token once and returning it on future ones instead.

**Main advantages of implementing JWT**

-   JWT tokens are stateless: the server does not maintain sessions.
-   Self-sufficient in identifying users and saving session/user lookups
-   Not relying on cookies means JWT tokens are **immune** to CSRF attacks.
-   Thanks to not maintaining cookies, JWT works very well with mobile apps.

## The basics of JWT

JWT stands for _JSON Web Token,_ which consists of three Base64 encoded, dot-separated parts:

-   Header
  -   The header typically consists of two parts: the type of the token, which is JWT, and the algorithm that is used, such as HMAC SHA256 or RSA SHA256. It is Base64Url encoded to form the first part of the JWT.
-   Payload
	-   The payload contains the claims. There is a set of registered claims, for example: iss (issuer), exp (expiration time), sub (subject), and aud (audience). These claims are not mandatory but recommended to provide a set of useful, interoperable claims. The payload can also include extra attributes that define custom claims, such as employee role. Typically, the subject claim is used to create the OpenID Connect user subject. However, the Liberty JVM server can be configured to use an alternative claim. The payload is Base64Url encoded to form the second part of the JWT.
-   Signature
	-   To create the signature part, the encoded header and encoded payload are signed by using the signature algorithm from the header. The signature is used to verify that the issuer of the JWT is who it says it is and to ensure that the message wasn't changed along the way.

The token returned by the API is an encoded string that comprises three different sections separated from each other by a dot character:

_`HEADER.PAYLOAD.SIGNATURE`_

# Using JWT for API authentication

JWT technology became incredibly popular. Even Google uses it to let you authenticate to its APIs.

The process goes as follows: on the client side, you create the token using the secret token to sign it.

When you pass it as part of the API request, the server will know which specific client is by reading the request signature containing its unique identifier.

## Securing a secret API: Example

As stated before, any interaction with our secure API would start with a login request, which would look something like the following:

**Route:** `POST /API/v1/users/login`

**Payload:**
```
    {
    "nickname": "John Doe"
    "password": "dummy_password"
    }
```
_If credentials are valid, the API will return a new JWT._

`Iss`: Contains the username of the logged-in user, which is especially useful since we might want to show that in our UI

`Exp`: defines the token active duration.

`Admin`: Boolean describing the role of the user.

```
    // Header
    {
      “alg”: “HS256”,
      “typ”: “JWT”
    }

    // Payload
    {
      “Iss”: “John Doe”
      “Exp”: 1550946689,
      “Admin”: false
    }
```
_To create the actual token, we need to encode the items above and then sign the resulting values to add the final piece to the Token:_
```
    Base64(header) = ewoiYWxnIjogIkhTMjU2IiwKInR5cCI6ICJKV1QiCn0K

    Base64(payload) = ewoiSXNzIjogImZlcm5hbmRvIiwKIkV4cCI6IDE1NTA5NDY2ODksCiJBZG1pbiI6IGZhbHNlCn0K

    HS256(Base64(header) + “.” + Base64(payload), “Seta API example”) = TseARzVBAtDbU8f3TEiRgsUoKYaW2SbhCWB0QlKpdp8
```
_The code below shows the final JWT returned by the API:_

`ewoiYWxnIjogIkhTMjU2IiwKInR5cCI6ICJKV1QiCn0K.ewoiSXNzIjogImZlcm5hbmRvIiwKIkV4cCI6IDE1NTA5NDY2ODksCiJBZG1pbiI6IGZhbHNlCn0K.TseARzVBAtDbU8f3TEiRgsUoKYaW2SbhCWB0QlKpdp8`

In a typical JWT request, the JWT would be sent as part of the authorization header on the client side after the client logged in, like `Authorization:Bearer`

## Implementing JWT on a Rails API: Example

 **What we need:**
-   Ruby 2.5.1
-   Rails 5.2.1
-   PostgreSQL
-   Postman

**Rest API Table**

| URL / ENDPOINT    | VERB   | DESCRIPTION      |
|-------------------|--------|------------------|
| /auth/login       | POST   | Generate token   |
| /users            | POST   | Create user      |
| /users            | GET    | Return all users |
| /users/{username} | GET    | Return user      |
| /users/{username} | PUT    | Update user      |
| /users/{username} | DELETE | Destroy user     |

Generate the Rails project typting the following on the terminal: `$ rails new rails-jwt --api`
Add JSON Web Token (JWT) and bcrypt gem.
-   JWT: Open industry standard (RFC 7519) for representing claims securely between two parties
-   bcrypt : Password hashing algorithm

```
    # Use Json Web Token (JWT) for token based authentication
    gem 'jwt'
    # Use ActiveModel has_secure_password
    gem 'bcrypt', '~> 3.1.7'
```
then install dependencies by typing this on your terminal

`$ bundle install`

**Update routes:**
```
# config/routes.rb
  Rails.application.routes.draw do
    resources :users, param: :_username
    post '/auth/login', to: 'authentication#login'
    get '/*a', to: 'application#not_found'
  end
```

In the routes.rb, we defined routes for users using resources. resources syntax helps us for generating REST API design for the user using _username as a parameter. So it will look like our REST API table above.

**Create JsonWebToken class**
```
class JsonWebToken
  SECRET_KEY = Rails.application.secrets.secret_key_base. to_s

  def self.encode(payload, exp = 24.hours.from_now)
    payload[:exp] = exp.to_i
    JWT.encode(payload, SECRET_KEY)
  end

  def self.decode(token)
    decoded = JWT.decode(token, SECRET_KEY)[0]
    HashWithIndifferentAccess.new decoded
  end
end
```
`SECRET_KEY` is the key for encoding and decoding tokens. In the code above, we assign a secret key generated by default by rails application into the `SECRET_KEY` variable. `SECRET_KEY` must be secret and not to be shared. Every time we’re doing some encoding and decoding using JWT, we need to specify the `SECRET_KEY`. By grouping and encapsulating the JWT encoding and decoding mechanism in this class, we will reduce a couple of codes that have responsibility for doing encoding and decoding jobs, because we don’t need to specify `SECRET_KEY` every time. The decode and encode function above is defined as a static function because it will give flexibility for doing encoding and decoding jobs without instantiating the JsonWebToken object.

self.encode function has 2 parameters. first payload and second exp. Payload is a key-value object for holding data that want to be encoded. exp stand for expiration for holding expiration time token. if exp is not specified it will give you the default value in 24 hours or one day.

In self.decode function we decoded the token given by the user and get the first value then assign it to a decoded variable, the first value contains a payload that we had already encoded before and the second value contain information about the algorithm that we use for encoding and decoding token.

**Create authorize_request function**
```
class ApplicationController < ActionController::API

  def not_found
    render json: { error: 'not_found' }
  end

  def authorize_request
    header = request.headers['Authorization']
    header = header.split(' ').last if header
    begin
      @decoded = JsonWebToken.decode(header)
      @current_user = User.find(@decoded[:user_id])
    rescue ActiveRecord::RecordNotFound => e
      render json: { errors: e.message }, status: :unauthorized
    rescue JWT::DecodeError => e
      render json: { errors: e.message }, status: :unauthorized
    end
  end
end
```

`authorize_request` function has responsibility for authorizing user requests. first, we need to get a token in the header with ‘Authorization’ as a key. with this token now we can decode and get the payload value. In this application, we define user_id in the payload. You should not include the user credentials data into the payload because it will cause security issues, you can include data that is needed to authorize the user. When performing JsonWebToken.decode function, it will return `JWT::DecodeError` if there was an error like token was expired, token not valid, token missing, etc. After we got user_id from the payload then we will try to find the user by id and assign it into current_user variable, If the user does not exist it will return `ActiveRecord::RecordNotFound` and it will render an error message with HTTP status unauthorized.

**Create user model**
`$ rails g model user name:string username:string email:string password_digest:string`
add user validation
```
class User < ApplicationRecord
  has_secure_password
  mount_uploader :avatar, AvatarUploader
  validates :email, presence: true, uniqueness: true
  validates :email, format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :username, presence: true, uniqueness: true
  validates :password,
            length: { minimum: 6 },
            if: -> { new_record? || !password.nil? }
end
```

**Create user controller**
`$ rails g controller users`
Add Create, Read, Update, Delete (CRUD ) functionality
```
class UsersController < ApplicationController
  before_action :authorize_request, except: :create
  before_action :find_user, except: %i[create index]

  # GET /users
  def index
    @users = User.all
    render json: @users, status: :ok
  end

  # GET /users/{username}
  def show
    render json: @user, status: :ok
  end

  # POST /users
  def create
    @user = User.new(user_params)
    if @user.save
      render json: @user, status: :created
    else
      render json: { errors: @user.errors.full_messages },
             status: :unprocessable_entity
    end
  end

  # PUT /users/{username}
  def update
    unless @user.update(user_params)
      render json: { errors: @user.errors.full_messages },
             status: :unprocessable_entity
    end
  end

  # DELETE /users/{username}
  def destroy
    @user.destroy
  end

  private

  def find_user
    @user = User.find_by_username!(params[:_username])
    rescue ActiveRecord::RecordNotFound
      render json: { errors: 'User not found' }, status: :not_found
  end

  def user_params
    params.permit(
      :avatar, :name, :username, :email, :password, :password_confirmation
    )
  end
end
```
**Create authentication controller**
`$ rails g controller authentication`
Implement login feature
```
class AuthenticationController < ApplicationController
  before_action :authorize_request, except: :login

  # POST /auth/login
  def login
    @user = User.find_by_email(params[:email])
    if @user&.authenticate(params[:password])
      token = JsonWebToken.encode(user_id: @user.id)
      time = Time.now + 24.hours.to_i
      render json: { token: token, exp: time.strftime("%m-%d-%Y %H:%M"),
                     username: @user.username }, status: :ok
    else
      render json: { error: 'unauthorized' }, status: :unauthorized
    end
  end

  private

  def login_params
    params.permit(:email, :password)
  end
end
```

## **Considerations:**

There is a cost involved in using JWTs: as they travel on every request to the server, there is a higher cost than server-side sessions.

While the security risks decrease sending JWTs using HTTPS, there is always the possibility that it gets intercepted and the data deciphered, exposing the user data.

Make sure that the issuer is being always checked. When using the JWT you should be sure that it has been issued by someone you expected to issue it. This is especially important if you adhere to another good practice and dynamically download the keys needed to validate / decrypt the tokens. If someone should send you a forged JWT, put their issuer in, and you then download keys from that issuer, then your application would validate the JWTs and accept them as genuine.

Use tokens as they are intented. E.g. that you won't accept an ID Token JWT as an Access Token.

JWTs are self-contained, by-value tokens and it is very hard to revoke them, once issued and delivered to the recipient. Because of that, you should use as short expiration time for your tokens as possible — minutes or hours at maximum. You should avoid giving your tokens expiration times in days or months.

In JWT there is no way to invalidate token, you can use one of these approaches to implement the logout feature :

1. Remove token from the client, but token still valid, in my opinion, you should use short time period token.
2. Add token into blacklist, when token added into blacklist token still valid until expiration time but you can deny this request from accessing the resource.

## **Conclusion:**
In conclusion, JWT is a powerful tool for handling authentication and authorization in web applications. They allow for decentralized authentication, are self-contained, and can improve performance and scalability. However, care must be taken to properly secure JWT to prevent potential attacks.
