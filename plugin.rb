# name: discourse-migratepassword-custom
# about: enable alternative password hashes
# version: 0.2
# authors: Jens Maier and Michael@discoursehosting.com
# url: https://github.com/Doss/discourse-migratepassword

# Usage:
# When migrating, store a custom field with the user containing the crypted password
# for homemade                      #{salt}:#{hash}          md5(md5(salt)+md5(pass))

#This will be applied at runtime, as authentication is attempted.  It does not apply at migration time.

gem 'bcrypt', '3.1.3'
gem 'unix-crypt', '1.3.0', :require_name => 'unix_crypt'

enabled_site_setting :migratepassword_enabled

require 'digest'

after_initialize do
 
    module ::AlternativePassword
        def confirm_password?(password)
            return true if super
            return false unless SiteSetting.migratepassword_enabled
            return false unless self.custom_fields.has_key?('import_pass')

            if AlternativePassword::check_all(password, self.custom_fields['import_pass'])
                self.password = password
                self.custom_fields.delete('import_pass')

                if SiteSetting.migratepassword_allow_insecure_passwords
                    return save(validate: false)
                else
                    return save
                end
            end
            false
        end
 
        def self.check_all(password, crypted_pass)
            AlternativePassword::check_homemade(password, crypted_pass) 
        end

        def self.check_homemade(password, crypted_pass)
            # we can't use split since the salts may contain a colon
            salt = crypted_pass.rpartition('¤').first
            hash = crypted_pass.rpartition('¤').last
            !salt.nil? && hash == Digest::MD5.hexdigest(Digest::MD5.hexdigest(salt) + Digest::MD5.hexdigest(password))
        end
    end
 
    class ::User
        prepend AlternativePassword
    end
 
end
