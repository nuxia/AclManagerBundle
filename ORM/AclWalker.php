<?php

namespace Problematic\AclManagerBundle\ORM;

use Doctrine\ORM\Mapping\ClassMetadataInfo;
use Doctrine\ORM\Query;
use Doctrine\ORM\Query\SqlWalker;

class AclWalker extends SqlWalker
{
    /**
     * @param \Doctrine\ORM\Query\AST\WhereClause $whereClause
     *
     * @return string
     */
    public function walkWhereClause($whereClause)
    {
        $sql = parent::walkWhereClause($whereClause);
        $query = $this->getQuery();

        $extraCriteria = $query->getHint(AclFilter::ACL_EXTRA_CRITERIA);

        if($extraCriteria instanceof \Closure){
            $criteria = new ExtraAclCriteria($query, $this);
            $extraCriteria($whereClause, $criteria);

            $sql .= ' '.$criteria->getExpression().' ';
        }

        return $sql;
    }

    /**
     * @param $fromClause
     *
     * @return string
     */
    public function walkFromClause($fromClause)
    {
        $sql = parent::walkFromClause($fromClause);
        $query = $this->getQuery();
        $alias = $query->getHint(AclFilter::ACL_IDENTIFIER_ALIAS);
        $identities = $query->getHint(AclFilter::ACL_IDENTIFIERS);
        $mask = $query->getHint(AclFilter::ACL_MASK);

        $sql .= ' INNER JOIN acl_object_identities as o ON o.object_identifier = '.$this->getSQLTableAlias($this->getTableNameFromAlias($alias), $alias).'.id ';
        $sql .= ' INNER JOIN acl_classes c ON c.id = o.class_id ';
        $sql .= ' LEFT JOIN acl_entries e ON (e.mask >= '.$mask.' AND e.class_id = o.class_id AND (e.object_identity_id = o.id OR e.object_identity_id IS NULL )) ';
        $sql .= ' LEFT JOIN acl_security_identities s ON (s.id = e.security_identity_id AND s.identifier IN ('.implode(', ', $identities).')) ';

        return $sql;
    }

    /**
     * @param $alias
     *
     * @return string
     * @throws \Exception
     */
    protected function getTableNameFromAlias($alias)
    {
        $metadata = $this->getQueryComponents('metadata');

        if(isset($metadata[$alias]['metadata'])){
            /** @var ClassMetadataInfo */
            $metadataClass = $metadata[$alias]['metadata'];
            return $metadataClass->getTableName();
        }

        throw new \Exception('Unable to retrieve table name');
    }
}
