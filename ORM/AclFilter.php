<?php

namespace Problematic\AclManagerBundle\ORM;

use Doctrine\Common\Persistence\AbstractManagerRegistry;
use Doctrine\Common\Persistence\Mapping\ClassMetadata;
use Doctrine\ORM\AbstractQuery;
use Doctrine\ORM\Query;
use Doctrine\ORM\QueryBuilder;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class AclFilter
{
    /** @var \Doctrine\Common\Persistence\ObjectManager */
    protected $em;

    /** @var SecurityContextInterface  */
    protected $securityContext;

    /** @var object  */
    protected $aclConnection;

    /** @var  AclWalker */
    protected $aclWalker;

    /** @var  array */
    protected $roleHierarchy;

    const ACL_IDENTIFIERS = 'acl_identifiers';
    const ACL_MASK = 'acl_mask';
    const ACL_IDENTIFIER_ALIAS = 'acl_identifier_alias';
    const ACL_EXTRA_CRITERIA = 'acl_extra_criteria';

    /**
     * @param AbstractManagerRegistry  $doctrineRegistry
     * @param SecurityContextInterface $securityContext
     * @param array                    $options
     */
    public function __construct(
        AbstractManagerRegistry $doctrineRegistry,
        SecurityContextInterface $securityContext,
        Array $options = array()
    ) {
        $this->em = $doctrineRegistry->getManager();
        $this->securityContext = $securityContext;
        $this->aclConnection = $doctrineRegistry->getConnection('default'); //wrong, must retrieve conn from acl conf
        list($this->aclWalker, $this->roleHierarchy) = $options;
    }

    /**
     * @param Query|QueryBuilder      $query
     * @param array $permissions
     * @param string  $identity
     * @param string  $alias
     *
     * @return AbstractQuery
     * @throws \Exception
     */
    public function apply(
        $query,
        array $permissions = array('VIEW'),
        $identity = null,
        $alias = null,
        \Closure $extraCriteria = null
    ) {
        if (null === $identity) {
            $token = $this->securityContext->getToken();
            $identity = $token->getUser();
        }

        if ($query instanceof QueryBuilder) {
            $query = $query->getQuery();
        }

        if(!$query instanceof Query) {
            throw new \Exception();
        }

        $maskBuilder = new MaskBuilder();

        foreach ($permissions as $permission) {
            $mask = constant(get_class($maskBuilder) . '::MASK_' . strtoupper($permission));
            $maskBuilder->add($mask);
        }

        $query->setHint(static::ACL_IDENTIFIERS, $this->getIdentifiers($identity));
        $query->setHint(static::ACL_MASK, $maskBuilder->get());
        $query->setHint(static::ACL_IDENTIFIER_ALIAS, $alias);
        $query->setHint(static::ACL_EXTRA_CRITERIA, $extraCriteria);
        $query->setHint(Query::HINT_CUSTOM_OUTPUT_WALKER, $this->aclWalker);

        return $query;
    }

    /**
     * Get ACL compatible classes for specified class metadata
     *
     * @param  ClassMetadata $metadata
     * @return array
     */
    protected function getClasses(ClassMetadata $metadata)
    {
        $classes = array();
        foreach ($metadata->subClasses as $subClass) {
            $classes[] = '"' . str_replace('\\', '\\\\', $subClass) . '"';
        }
        $classes[] = '"' . str_replace('\\', '\\\\', $metadata->name) . '"';

        return $classes;
    }

    /**
     * Get security identifiers associated with specified identity
     *
     * @param  UserInterface | string $identity
     * @return array
     */
    protected function getIdentifiers($identity)
    {
        $userClass = array();

        if ($identity instanceof UserInterface) {
            $roles = $identity->getRoles();
            $userClass[] = '"' . str_replace('\\', '\\\\', get_class($identity)) . '-' . $identity->getUserName() . '"';
        } elseif (is_string($identity)) {
            $roles = array($identity);
        } else {
            return array();
        }

        $resolvedRoles = array();

        foreach ($roles as $role) {
            $resolvedRoles[] = '"' . $role . '"';
            $resolvedRoles = array_merge($resolvedRoles, $this->resolveRoles($role));
        }

        $identifiers = array_merge($userClass, array_unique($resolvedRoles));

        return $identifiers;
    }

    /**
     * Get parent roles of the specified role
     *
     * @param  string $role
     * @return array
     */
    protected function resolveRoles($role)
    {
        $hierarchy = $this->roleHierarchy;
        $roles = array();
        if (array_key_exists($role, $hierarchy)) {
            foreach ($hierarchy[$role] as $parent_role) {
                $roles[] = '"' . $parent_role . '"';
                $roles = array_merge($roles, $this->resolveRoles($parent_role));
            }
        }

        return $roles;
    }
}
