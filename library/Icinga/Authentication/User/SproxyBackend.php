<?php
/* 2016 Zalora South East Asia Pte. Ltd | GPLv2+ */

namespace Icinga\Authentication\User;

use Icinga\Data\ConfigObject;
use Icinga\User;

/**
 * Login with Sproxy authentication mechanism.
 * This is similar to the "external" backend.
 *
 * Sproxy provides at least two HTTP headers:
 *
 * "From" - the user's email address.
 * "X-Groups" - a comma-separated list of the user's groups.
 *
 *
 * See <https://hackage.haskell.org/package/sproxy2>,
 *  or <https://github.com/ip1981/sproxy2>,
 *  or <https://gitlab.com/ip1981/sproxy2>,
 *  or <https://bitbucket.org/IgorPashev/sproxy2>.
 */
class SproxyBackend extends ExternalBackend
{
    /**
     * {@inheritdoc}
     */
    public function authenticate(User $user, $password = null)
    {
        if (! empty($_SERVER['HTTP_FROM'])) {
            $email = $_SERVER['HTTP_FROM'];
            $user->setUsername($email);
            $user->setEmail($email);
            $user->setExternalUserInformation($email, 'HTTP_FROM');

            if (! empty($_SERVER['HTTP_X_GIVEN_NAME'])) {
              $user->setFirstname($_SERVER['HTTP_X_GIVEN_NAME']);
            }
            if (! empty($_SERVER['HTTP_X_GROUPS'])) {
              $user->setGroups(explode(',', $_SERVER['HTTP_X_GROUPS']));
            }
            if (! empty($_SERVER['HTTP_X_FAMILY_NAME'])) {
              $user->setLastname($_SERVER['HTTP_X_FAMILY_NAME']);
            }

            return true;
        }
        return false;
    }
}
