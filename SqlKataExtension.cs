namespace <#= ProjectNamespace #>.Models
{
    public static class SqlKataExtension
    {
        public static SqlKata.Query Query<TEntity>(this DbTable dbTable,string alias="") where TEntity : class
        {
            var db = Build<DbTable>(dbTable);
            SqlKata.Query q = db.Query(ResolveTableName<TEntity>(alias));
            return q;
        }

        public static SqlKata.Query Query<TEntity>(this SqlKata.Execution.QueryFactory factory, string alias = "") where TEntity : class
        {
           
            SqlKata.Query q = factory.Query(ResolveTableName<TEntity>());
            return factory.Query(ResolveTableName<TEntity>(alias));
        }


        public static SqlKata.Execution.QueryFactory Build<T>(this T dbTable) where T: DbTable
        {
            return dbTable.GetQueryFactory(false);
        }
    }
}
