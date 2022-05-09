<?php
/**
 * @copyright Copyright (c) 2016 Lukas Reschke <lukas@statuscode.ch>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\User_SAML\AppInfo;

use OC;
use OC\Security\CSRF\CsrfTokenManager;
use OC_User;
use OCA\Files\Event\LoadAdditionalScriptsEvent;
use OCA\User_SAML\DavPlugin;
use OCA\User_SAML\Middleware\OnlyLoggedInMiddleware;
use OCA\User_SAML\SAMLSettings;
use OCA\User_SAML\UserBackend;
use OCA\User_SAML\UserData;
use OCA\User_SAML\UserResolver;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\AppFramework\IAppContainer;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\IGroupManager;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Util;
use Psr\Log\LoggerInterface;
use Throwable;

require_once __DIR__ . '/../../3rdparty/vendor/autoload.php';

class Application extends App implements IBootstrap {
	public function __construct(array $urlParams = []) {
		parent::__construct('user_saml', $urlParams);
		$container = $this->getContainer();

		/**
		 * Middleware
		 */
		$container->registerService('OnlyLoggedInMiddleware', function (IAppContainer $c) {
			return new OnlyLoggedInMiddleware(
				$c->query('ControllerMethodReflector'),
				$c->query('ServerContainer')->getUserSession(),
				$c->query('ServerContainer')->getUrlGenerator()
			);
		});

		$container->registerService(DavPlugin::class, function (IAppContainer $c) {
			$server = $c->getServer();
			return new DavPlugin(
				$server->getSession(),
				$server->getConfig(),
				$_SERVER,
				$server->get(SAMLSettings::class)
			);
		});

		$container->registerMiddleWare('OnlyLoggedInMiddleware');
		$this->timezoneHandling();
	}

	private function timezoneHandling() {
		$container = $this->getContainer();

		$userSession = $container->getServer()->getUserSession();
		$session = $container->getServer()->getSession();
		$config = $container->getServer()->getConfig();

		/** @var IEventDispatcher $dispatcher */
		$dispatcher = $container->getServer()->get(IEventDispatcher::class);
		$dispatcher->addListener(LoadAdditionalScriptsEvent::class, function () use ($session, $config, $userSession): void {
			if (!$userSession->isLoggedIn()) {
				return;
			}

			$user = $userSession->getUser();
			$timezoneDB = $config->getUserValue($user->getUID(), 'core', 'timezone', '');

			if ($timezoneDB === '' || !$session->exists('timezone')) {
				Util::addScript('user_saml', 'vendor/jstz.min');
				Util::addScript('user_saml', 'timezone');
			}
		});
	}

	public function register(IRegistrationContext $context): void {
		// TODO: Implement register() method.
	}

	public function boot(IBootContext $context): void {
		try {
			$context->injectFn(function (
				IURLGenerator $urlGenerator,
				IConfig $config,
				IRequest $request,
				IUserSession $userSession,
				ISession $session,
				IFactory $factory,
				SAMLSettings $samlSettings,
				IUserManager $userManager,
				IDBConnection $connection,
				LoggerInterface $logger,
				IGroupManager $groupManager,
				IEventDispatcher $dispatcher,
				CsrfTokenManager $csrfTokenManager
			) {
				// If we run in CLI mode do not setup the app as it can fail the OCC execution
				// since the URLGenerator isn't accessible.
				$cli = false;
				if (OC::$CLI) {
					$cli = true;
				}
				$l = $factory->get('user_saml');

				$userData = new UserData(
					new UserResolver($userManager),
					$samlSettings,
					$config
				);

				$userBackend = new UserBackend(
					$config,
					$urlGenerator,
					$session,
					$connection,
					$userManager,
					$groupManager,
					$samlSettings,
					$logger,
					$userData,
					$dispatcher
				);
				$userBackend->registerBackends($userManager->getBackends());
				OC_User::useBackend($userBackend);

				$params = [];

				// Setting up the one login config may fail, if so, do not catch the requests later.
				$returnScript = false;
				switch ($config->getAppValue('user_saml', 'type')) {
					case 'saml':
						$type = 'saml';
						break;
					case 'environment-variable':
						$type = 'environment-variable';
						break;
					default:
						return;
				}

				if ($type === 'environment-variable') {
					// We should ignore oauth2 token endpoint (oauth can send the credentials as basic auth which will fail with apache auth)
					$uri = $request->getRequestUri();
					if (substr($uri, -24) === '/apps/oauth/api/v1/token') {
						return;
					}

					OC_User::handleApacheAuth();
				}

				$redirectSituation = false;

				$user = $userSession->getUser();
				if ($user !== null) {
					$enabled = $user->isEnabled();
					if ($enabled === false) {
						$targetUrl = $urlGenerator->linkToRouteAbsolute(
							'user_saml.SAML.genericError',
							[
								'message' => $l->t('This user account is disabled, please contact your administrator.')
							]
						);
						header('Location: ' . $targetUrl);
						exit();
					}
				}

				// All requests that are not authenticated and match against the "/login" route are
				// redirected to the SAML login endpoint
				if (!$cli &&
					!$userSession->isLoggedIn() &&
					($request->getPathInfo() === '/login'
						|| $request->getPathInfo() === '/login/v2/flow'
						|| $request->getPathInfo() === '/login/flow')) {
					try {
						$params = $request->getParams();
					} catch (\LogicException $e) {
						// ignore exception when PUT is called since getParams cannot parse parameters in that case
					}
					if (isset($params['direct'])) {
						return;
					}
					$redirectSituation = true;
				}

				// If a request to OCS or remote.php is sent by the official desktop clients it can
				// be intercepted as it supports SAML. All other clients don't yet and thus we
				// require the usage of application specific passwords there.
				//
				// However, it is an opt-in setting to use SAML for the desktop clients. For better
				// UX (users don't have to reauthenticate) we default to disallow the access via
				// SAML at the moment.
				$useSamlForDesktopClients = $config->getAppValue('user_saml', 'general-use_saml_auth_for_desktop', '0');
				if ($useSamlForDesktopClients === '1') {
					$currentUrl = substr(explode('?', $request->getRequestUri(), 2)[0], strlen(\OC::$WEBROOT));
					if (substr($currentUrl, 0, 12) === '/remote.php/' || substr($currentUrl, 0, 5) === '/ocs/') {
						if (!$userSession->isLoggedIn() && $request->isUserAgent([\OCP\IRequest::USER_AGENT_CLIENT_DESKTOP])) {
							$redirectSituation = true;

							if (preg_match('/^.*\/(\d+\.\d+\.\d+).*$/', $request->getHeader('USER_AGENT'), $matches) === 1) {
								$versionString = $matches[1];

								if (version_compare($versionString, '2.5.0', '>=') === true) {
									$redirectSituation = false;
								}
							}
						}
					}
				}

				$multipleUserBackEnds = $samlSettings->allowMultipleUserBackEnds();
				$configuredIdps = $samlSettings->getListOfIdps();
				$showLoginOptions = $multipleUserBackEnds || count($configuredIdps) > 1;

				if ($redirectSituation === true && $showLoginOptions) {
					try {
						$params = $request->getParams();
					} catch (\LogicException $e) {
						// ignore exception when PUT is called since getParams cannot parse parameters in that case
					}
					$redirectUrl = '';
					if (isset($params['redirect_url'])) {
						$redirectUrl = $params['redirect_url'];
					}

					$targetUrl = $urlGenerator->linkToRouteAbsolute(
						'user_saml.SAML.selectUserBackEnd',
						[
							'redirectUrl' => $redirectUrl
						]
					);
					header('Location: ' . $targetUrl);
					exit();
				}

				if ($redirectSituation === true) {
					try {
						$params = $request->getParams();
					} catch (\LogicException $e) {
						// ignore exception when PUT is called since getParams cannot parse parameters in that case
					}
					$originalUrl = '';
					if (isset($params['redirect_url'])) {
						$originalUrl = $urlGenerator->getAbsoluteURL($params['redirect_url']);
					}

					$csrfToken = $csrfTokenManager->getToken();
					$targetUrl = $urlGenerator->linkToRouteAbsolute(
						'user_saml.SAML.login',
						[
							'requesttoken' => $csrfToken->getEncryptedValue(),
							'originalUrl' => $originalUrl,
							'idp' => 1,
						]
					);
					header('Location: ' . $targetUrl);
					exit();
				}
			});
		} catch (Throwable $e) {
			OC::$server->get(LoggerInterface::class)->critical('Error when loading user_saml app', [
				'exception' => $e,
			]);
		}
	}
}
