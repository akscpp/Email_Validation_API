from validate_email import validate_email
from flask import Flask, request, jsonify, make_response
from flask_expects_json import expects_json
from jsonschema import validate, ValidationError
import smtplib
import dns.resolver

app = Flask(__name__)

# schema for JSON validation
schema = {
    "type": "object",
    "properties": {
        "email": {"type": "string"},
    },
    "required": ["email"]
}


def get_email_role(email):
    username = email.split('@')[0]
    role_emails = ['info', 'sales', 'support', 'contact', 'admin', 'webmaster', 'help', 'service', 'feedback', 'assistance', 'customer',
                   'care', 'inquiries', 'questions', 'billing', 'orders', 'returns', 'warranty', 'technical', 'repair', 'parts',
                   'installation', 'training', 'marketing', 'media', 'press', 'accountmanager', 'billingspecialist', 'clientrelations',
                   'complianceofficer', 'consultant', 'contentmanager', 'dataanalyst', 'developer', 'dispatchcoordinator',
                   'documentationspecialist', 'escalationmanager', 'implementationspecialist', 'incidentresponder', 'itsupport',
                   'knowledgebasemanager', 'localizationspecialist', 'networkadministrator', 'onboardingspecialist', 'productmanager',
                   'qualityassuranceanalyst', 'relationshipmanager', 'salesrepresentative', 'socialmediacoordinator', 'subjectmatterexpert',
                   'technicalwriter', 'trainingcoordinator', 'userexperience', 'vendormanager', 'virtualassistant', 'servicehead']
    for role_email in role_emails:
        if role_email in username:
            return role_email
    return None


def get_email_reputation(email):
    keys = email.split('@')[0]
    spam_keywords = ['spam', 'scam', 'phishing', 'fraud', 'fake', 'unauthorized', 'suspicious', 'malware', 'virus', 'spoof', 'danger', 'alert',
                     'pharmacy', 'lottery', 'inheritance', 'banking', 'loan', 'credit', 'insurance', 'guarantee', 'earn', 'money', 'cash',
                     'investment', 'opportunity', 'discount', 'free', 'limited time', 'urgent', 'secret', 'confidential', 'click', 'win',
                     'prize', 'claim', 'offer', 'exclusive', 'bargain', 'rich', 'online', 'income', 'job', 'winning', 'jackpot', 'claim',
                     'winner', 'expire', 'payment', 'bank', 'account', 'password', 'verify', 'update', 'sweepstakes', 'contest', 'congratulations',
                     'debt', 'weight loss', 'diet', 'miracle', 'enhancement', 'pharmaceutical', 'cialis', 'enhance', 'satisfaction',
                     'mortgage', 'refund', 'cure', 'solution', 'discount', 'cashback', 'refund', 'unclaimed', 'voucher', 'urgent', 'limited offer']
    for keyword in spam_keywords:
        if keyword in keys:
            return 'Spam'
    return 'Not Spam'


@app.route('/email-valid', methods=['POST'])
# Passing the required schema for JSON validation
@expects_json(schema)
def validate_email_address():
    try:

        email = request.json['email']
        is_valid = False
        exists = False

        is_valid = validate_email(email, verify=False)

        domain = email.split('@')[1]

        if is_valid:
            try:
                # Resolving MX records for the email domain
                #  Why it is important to check MX (Mail exchange) records?
                # It gives information about the email server responsible for handling incoming email for a specific domain
                domain = email.split('@')[1]
                mx_records = dns.resolver.resolve(domain, 'MX')
                # The dns.resolver.resolve() function queries the DNS system to retrieve the MX records associated with the domain.

                # Connect to the email server for checking MX records
                for mx in mx_records:
                    try:
                        with smtplib.SMTP() as server:
                            server.connect(mx.exchange.to_text())
                            server.helo(domain)
                            server.mail('test@example.com')
                            code, _ = server.rcpt(str(email))

                            # Check if the email address exists
                            if code == 250:
                                exists = True
                                break

                    except smtplib.SMTPException:
                        # Handle SMTP-related errors
                        return jsonify({'error': 'Email validation failed. SMTP error occurred.'}), 500

            except dns.resolver.NXDOMAIN:
                # Handle unknown domains
                domain = 'Unknown'
                exists = False

            except dns.exception.DNSException:
                # Handle DNS-related errors
                return jsonify({'error': 'Email validation failed. DNS error occurred.'}), 500

        role = get_email_role(email)
        reputation = get_email_reputation(email)
        if role is None:
            role = "personal"

        # Return the validation result as JSON
        return jsonify({
            'email': email,
            'domain': domain,
            'exists': exists,
            'valid': is_valid,
            'role': role,
            'reputation': reputation
        })

    except ValidationError as e:
        # Return the validation error message as JSON
        return make_response(jsonify({'error': e.message}), 400)

    except Exception as e:
        # Return the error message as JSON
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
